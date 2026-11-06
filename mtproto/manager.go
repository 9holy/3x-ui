package mtproto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"x-ui/config"
	"x-ui/database/model"
	"x-ui/logger"
)

const Protocol model.Protocol = "mtproto"

type instance struct {
	id     int
	listen string
	port   int
	secret string
}

type Manager struct {
	mu    sync.Mutex
	procs map[int]*Process
}

var singleton = &Manager{procs: map[int]*Process{}}

func GetManager() *Manager { return singleton }

func configDir() string {
	return filepath.Join(config.GetBinFolderPath(), "mtproto")
}

func configPath(id int) string {
	return filepath.Join(configDir(), fmt.Sprintf("mtg-%d.toml", id))
}

func parseInstance(inbound *model.Inbound) (instance, bool) {
	if inbound == nil || inbound.Protocol != Protocol || !inbound.Enable {
		return instance{}, false
	}
	var settings struct {
		Secret string `json:"secret"`
	}
	if json.Unmarshal([]byte(inbound.Settings), &settings) != nil || settings.Secret == "" {
		return instance{}, false
	}
	return instance{id: inbound.Id, listen: inbound.Listen, port: inbound.Port, secret: settings.Secret}, true
}

func writeConfig(inst instance) error {
	if err := os.MkdirAll(configDir(), 0o750); err != nil {
		return err
	}
	listen := inst.listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	content := fmt.Sprintf("secret = %q\nbind-to = %q\n", inst.secret, fmt.Sprintf("%s:%d", listen, inst.port))
	return os.WriteFile(configPath(inst.id), []byte(content), 0o640)
}

func (m *Manager) Reconcile(inbounds []*model.Inbound) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wanted := map[int]instance{}
	for _, inbound := range inbounds {
		if inst, ok := parseInstance(inbound); ok {
			wanted[inst.id] = inst
		}
	}
	for id, proc := range m.procs {
		if _, ok := wanted[id]; !ok {
			_ = proc.Stop()
			delete(m.procs, id)
			_ = os.Remove(configPath(id))
		}
	}
	for id, inst := range wanted {
		if proc := m.procs[id]; proc != nil && proc.Running() {
			continue
		}
		if err := writeConfig(inst); err != nil {
			logger.Warning("mtproto config failed:", err)
			continue
		}
		proc := newProcess(configPath(id))
		if err := proc.Start(); err != nil {
			logger.Warning("mtproto start failed:", err)
			continue
		}
		m.procs[id] = proc
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
}
