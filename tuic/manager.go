package tuic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"x-ui/config"
	"x-ui/logger"
)

const Protocol = "tuic"

type Inbound struct {
	Id       int
	Listen   string
	Port     int
	Protocol string
	Enable   bool
	Settings string
}

type instance struct {
	id     int
	listen string
	port   int
	config []byte
	digest string
}

type Manager struct {
	mu    sync.Mutex
	procs map[int]*Process
	state map[int]string
}

var singleton = &Manager{procs: map[int]*Process{}, state: map[int]string{}}

func GetManager() *Manager     { return singleton }
func configDir() string        { return filepath.Join(config.GetBinFolderPath(), "tuic") }
func configPath(id int) string { return filepath.Join(configDir(), fmt.Sprintf("tuic-%d.json", id)) }
func binaryPath() string {
	return filepath.Join(config.GetBinFolderPath(), fmt.Sprintf("tuic-server-linux-%s", runtime.GOARCH))
}

func parseInstance(inbound *Inbound) (instance, bool) {
	if inbound == nil || inbound.Protocol != Protocol || !inbound.Enable {
		return instance{}, false
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal([]byte(inbound.Settings), &settings) != nil || settings == nil {
		return instance{}, false
	}
	if _, ok := settings["server"]; !ok {
		listen := inbound.Listen
		if listen == "" {
			listen = "0.0.0.0"
		}
		server, _ := json.Marshal(fmt.Sprintf("%s:%d", listen, inbound.Port))
		settings["server"] = server
	}
	configJSON, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return instance{}, false
	}
	hash := sha256.Sum256(configJSON)
	return instance{id: inbound.Id, listen: inbound.Listen, port: inbound.Port, config: configJSON, digest: hex.EncodeToString(hash[:])}, true
}

func writeConfig(inst instance) error {
	if err := os.MkdirAll(configDir(), 0o750); err != nil {
		return err
	}
	return os.WriteFile(configPath(inst.id), inst.config, 0o640)
}

func (m *Manager) Reconcile(inbounds []Inbound) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wanted := map[int]instance{}
	for _, inbound := range inbounds {
		if inst, ok := parseInstance(&inbound); ok {
			wanted[inst.id] = inst
		}
	}
	for id, proc := range m.procs {
		if _, ok := wanted[id]; !ok {
			_ = proc.Stop()
			delete(m.procs, id)
			delete(m.state, id)
			_ = os.Remove(configPath(id))
		}
	}
	for id, inst := range wanted {
		if proc := m.procs[id]; proc != nil && proc.Running() && m.state[id] == inst.digest {
			continue
		}
		if proc := m.procs[id]; proc != nil {
			_ = proc.Stop()
		}
		if err := writeConfig(inst); err != nil {
			logger.Warning("tuic config failed:", err)
			continue
		}
		proc := newProcess(configPath(id))
		if err := proc.Start(); err != nil {
			logger.Warning("tuic start failed:", err)
			continue
		}
		m.procs[id] = proc
		m.state[id] = inst.digest
	}
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, proc := range m.procs {
		_ = proc.Stop()
		_ = os.Remove(configPath(id))
	}
	m.procs = map[int]*Process{}
	m.state = map[int]string{}
}
