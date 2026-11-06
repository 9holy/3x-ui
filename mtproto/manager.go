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
	id      int
	listen  string
	port    int
	secrets []secretEntry
}

type secretEntry struct {
	name   string
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
		Secret  string `json:"secret"`
		Email   string `json:"email"`
		Clients []struct {
			Email  string `json:"email"`
			Secret string `json:"secret"`
			Enable bool   `json:"enable"`
		} `json:"clients"`
	}
	if json.Unmarshal([]byte(inbound.Settings), &settings) != nil {
		return instance{}, false
	}
	secrets := make([]secretEntry, 0, len(settings.Clients)+1)
	for _, client := range settings.Clients {
		if client.Enable || !hasEnableField([]byte(inbound.Settings), client.Email) {
			if client.Email != "" && client.Secret != "" {
				secrets = append(secrets, secretEntry{name: client.Email, secret: client.Secret})
			}
		}
	}
	if len(secrets) == 0 && settings.Secret != "" {
		name := settings.Email
		if name == "" {
			name = "default"
		}
		secrets = append(secrets, secretEntry{name: name, secret: settings.Secret})
	}
	if len(secrets) == 0 {
		return instance{}, false
	}
	return instance{id: inbound.Id, listen: inbound.Listen, port: inbound.Port, secrets: secrets}, true
}

func hasEnableField(raw []byte, email string) bool {
	var settings struct {
		Clients []struct {
			Email  string `json:"email"`
			Enable *bool  `json:"enable"`
		} `json:"clients"`
	}
	if json.Unmarshal(raw, &settings) != nil {
		return false
	}
	for _, client := range settings.Clients {
		if client.Email == email {
			return client.Enable != nil
		}
	}
	return false
}

func writeConfig(inst instance) error {
	if err := os.MkdirAll(configDir(), 0o750); err != nil {
		return err
	}
	listen := inst.listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	content := fmt.Sprintf("bind-to = %q\n\n[secrets]\n", fmt.Sprintf("%s:%d", listen, inst.port))
	for _, secret := range inst.secrets {
		content += fmt.Sprintf("%q = %q\n", secret.name, secret.secret)
	}
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
