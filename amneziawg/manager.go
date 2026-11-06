package amneziawg

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

const Protocol model.Protocol = "amneziawg"

type desired struct {
	id         int
	ifName     string
	config     string
	configPath string
}

type Manager struct {
	mu    sync.Mutex
	procs map[int]*Process
}

var singleton = &Manager{procs: map[int]*Process{}}

func GetManager() *Manager { return singleton }

func configDir() string { return filepath.Join(config.GetBinFolderPath(), "amneziawg") }

func configPath(id int) string { return filepath.Join(configDir(), fmt.Sprintf("awg-%d.conf", id)) }

func parseInbound(inbound *model.Inbound) (desired, bool) {
	if inbound == nil || inbound.Protocol != Protocol || !inbound.Enable {
		return desired{}, false
	}
	var settings struct {
		Interface  string `json:"interface"`
		Config     string `json:"config"`
		ConfigPath string `json:"configPath"`
	}
	if json.Unmarshal([]byte(inbound.Settings), &settings) != nil {
		return desired{}, false
	}
	if settings.Config == "" && settings.ConfigPath == "" {
		logger.Warningf("amneziawg inbound %d has no config or configPath", inbound.Id)
		return desired{}, false
	}
	if settings.Interface == "" {
		settings.Interface = fmt.Sprintf("awg%d", inbound.Id)
	}
	return desired{
		id:         inbound.Id,
		ifName:     settings.Interface,
		config:     settings.Config,
		configPath: settings.ConfigPath,
	}, true
}

func (m *Manager) Reconcile(inbounds []*model.Inbound) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wanted := make(map[int]desired)
	for _, inbound := range inbounds {
		if item, ok := parseInbound(inbound); ok {
			wanted[item.id] = item
		}
	}
	for id, proc := range m.procs {
		if _, ok := wanted[id]; !ok {
			_ = proc.Stop()
			delete(m.procs, id)
			_ = os.Remove(configPath(id))
		}
	}
	for id, item := range wanted {
		if proc := m.procs[id]; proc != nil && proc.Running() && proc.ConfigPath() == item.configPath && proc.Signature() == item.config {
			continue
		}
		if proc := m.procs[id]; proc != nil {
			_ = proc.Stop()
			delete(m.procs, id)
		}
		path, err := writeConfig(item)
		if err != nil {
			logger.Warning("amneziawg config failed:", err)
			continue
		}
		proc := newProcess(item.ifName, path, item.config)
		if err := proc.Start(); err != nil {
			logger.Warning("amneziawg start failed:", err)
			continue
		}
		m.procs[id] = proc
	}
}

func writeConfig(item desired) (string, error) {
	if item.configPath != "" {
		return item.configPath, nil
	}
	if err := os.MkdirAll(configDir(), 0o750); err != nil {
		return "", err
	}
	path := configPath(item.id)
	if err := os.WriteFile(path, []byte(item.config), 0o600); err != nil {
		return "", err
	}
	return path, nil
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
