package mtproto

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"x-ui/config"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/xray"
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
	ports map[int]int
	last  map[int]map[string]statsCounter
}

type statsCounter struct {
	Up   int64
	Down int64
}

var singleton = &Manager{procs: map[int]*Process{}, ports: map[int]int{}, last: map[int]map[string]statsCounter{}}

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

func writeConfig(inst instance, apiPort int) error {
	if err := os.MkdirAll(configDir(), 0o750); err != nil {
		return err
	}
	listen := inst.listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	content := fmt.Sprintf("bind-to = %q\napi-bind-to = %q\n\n[secrets]\n", fmt.Sprintf("%s:%d", listen, inst.port), fmt.Sprintf("127.0.0.1:%d", apiPort))
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
			delete(m.ports, id)
			delete(m.last, id)
			_ = os.Remove(configPath(id))
		}
	}
	for id, inst := range wanted {
		if proc := m.procs[id]; proc != nil && proc.Running() {
			continue
		}
		apiPort, err := freePort()
		if err != nil {
			logger.Warning("mtproto api port failed:", err)
			continue
		}
		if err := writeConfig(inst, apiPort); err != nil {
			logger.Warning("mtproto config failed:", err)
			continue
		}
		proc := newProcess(configPath(id))
		if err := proc.Start(); err != nil {
			logger.Warning("mtproto start failed:", err)
			continue
		}
		m.procs[id] = proc
		m.ports[id] = apiPort
		m.last[id] = map[string]statsCounter{}
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
	m.ports = map[int]int{}
	m.last = map[int]map[string]statsCounter{}
}

type statsResponse struct {
	Users map[string]struct {
		BytesIn  int64 `json:"bytes_in"`
		BytesOut int64 `json:"bytes_out"`
	} `json:"users"`
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// CollectTraffic returns deltas since the previous poll in the format used by
// the existing SQLite client_traffics updater.
func (m *Manager) CollectTraffic() []*xray.ClientTraffic {
	m.mu.Lock()
	ports := make(map[int]int, len(m.ports))
	last := make(map[int]map[string]statsCounter, len(m.last))
	for id, port := range m.ports {
		ports[id] = port
		last[id] = m.last[id]
	}
	m.mu.Unlock()

	type result struct {
		id    int
		users map[string]statsCounter
	}
	results := make([]result, 0, len(ports))
	for id, port := range ports {
		resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/stats")
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		var parsed statsResponse
		if json.Unmarshal(body, &parsed) != nil {
			continue
		}
		users := make(map[string]statsCounter, len(parsed.Users))
		for email, user := range parsed.Users {
			users[email] = statsCounter{Up: user.BytesIn, Down: user.BytesOut}
		}
		results = append(results, result{id: id, users: users})
	}

	traffic := make([]*xray.ClientTraffic, 0)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, item := range results {
		previous := last[item.id]
		for email, current := range item.users {
			old := previous[email]
			up, down := current.Up-old.Up, current.Down-old.Down
			if up > 0 || down > 0 {
				traffic = append(traffic, &xray.ClientTraffic{InboundId: item.id, Email: email, Up: up, Down: down})
			}
		}
		m.last[item.id] = item.users
	}
	return traffic
}
