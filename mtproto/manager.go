package mtproto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	mu      sync.Mutex
	poll    sync.Mutex
	procs   map[int]*Process
	ports   map[int]int
	last    map[int]map[string]statsCounter
	state   map[int]string
	tokens  map[int]string
	pending []*xray.ClientTraffic
}

type statsCounter struct {
	Up   int64
	Down int64
}

var singleton = newManager()

func newManager() *Manager {
	return &Manager{procs: map[int]*Process{}, ports: map[int]int{}, last: map[int]map[string]statsCounter{}, state: map[int]string{}, tokens: map[int]string{}}
}

func GetManager() *Manager { return singleton }

func configDir() string {
	return filepath.Join(config.GetBinFolderPath(), "mtproto")
}

func configPath(id int) string {
	return filepath.Join(configDir(), fmt.Sprintf("mtg-%d.toml", id))
}

type clientSettings struct {
	Email      string `json:"email"`
	Secret     string `json:"secret"`
	Enable     *bool  `json:"enable"`
	TotalGB    int64  `json:"totalGB"`
	ExpiryTime int64  `json:"expiryTime"`
}

type inboundSettings struct {
	Secret  string           `json:"secret"`
	Email   string           `json:"email"`
	Clients []clientSettings `json:"clients"`
}

// ValidSecret follows mtg-multi's FakeTLS parser, including unpadded base64url.
func ValidSecret(secret string) bool {
	decoded, err := hex.DecodeString(secret)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(secret)
	}
	return err == nil && len(decoded) > 17 && decoded[0] == 0xee
}

func ValidateSettings(raw string) error {
	var settings inboundSettings
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return fmt.Errorf("invalid MTProto settings: %w", err)
	}
	if settings.Clients == nil {
		if !ValidSecret(settings.Secret) {
			return fmt.Errorf("MTProto requires a valid FakeTLS secret or clients")
		}
		return nil
	}
	seen := map[string]bool{}
	for _, client := range settings.Clients {
		if client.Email == "" || seen[client.Email] {
			return fmt.Errorf("MTProto client email must be non-empty and unique")
		}
		if !ValidSecret(client.Secret) {
			return fmt.Errorf("MTProto client %q has an invalid FakeTLS secret", client.Email)
		}
		seen[client.Email] = true
	}
	return nil
}

func ValidateInbound(inbound *model.Inbound) error {
	if err := ValidateSettings(inbound.Settings); err != nil {
		return err
	}
	if inbound.Port < 1 || inbound.Port > 65535 {
		return fmt.Errorf("invalid MTProto port")
	}
	if inbound.Listen != "" && net.ParseIP(strings.Trim(inbound.Listen, "[]")) == nil {
		return fmt.Errorf("MTProto listen must be an IP address")
	}
	if _, active := parseInstance(inbound); active {
		if _, err := os.Stat(binaryPath()); err != nil {
			return fmt.Errorf("MTProto runtime is unavailable; install %s: %w", binaryPath(), err)
		}
	}
	return nil
}

func parseInstance(inbound *model.Inbound) (instance, bool) {
	if inbound == nil || inbound.Protocol != Protocol || !inbound.Enable ||
		(inbound.ExpiryTime > 0 && inbound.ExpiryTime <= time.Now().UnixMilli()) ||
		(inbound.Total > 0 && inbound.Up+inbound.Down >= inbound.Total) {
		return instance{}, false
	}
	var settings inboundSettings
	if json.Unmarshal([]byte(inbound.Settings), &settings) != nil {
		return instance{}, false
	}
	stats := map[string]xray.ClientTraffic{}
	for _, stat := range inbound.ClientStats {
		stats[stat.Email] = stat
	}
	now := time.Now().UnixMilli()
	secrets := make([]secretEntry, 0, len(settings.Clients)+1)
	for _, client := range settings.Clients {
		if (client.Enable != nil && !*client.Enable) ||
			(client.ExpiryTime > 0 && client.ExpiryTime <= now) {
			continue
		}
		if stat, ok := stats[client.Email]; ok && (!stat.Enable ||
			(stat.Total > 0 && stat.Up+stat.Down >= stat.Total) ||
			(client.TotalGB > 0 && stat.Up+stat.Down >= client.TotalGB) ||
			(stat.ExpiryTime > 0 && stat.ExpiryTime <= now)) {
			continue
		}
		if client.Email != "" && ValidSecret(client.Secret) {
			secrets = append(secrets, secretEntry{name: client.Email, secret: client.Secret})
		}
	}
	// A stale legacy secret must not resurrect an explicitly empty or disabled
	// clients list after the last client's access has been revoked.
	if settings.Clients == nil && ValidSecret(settings.Secret) {
		name := settings.Email
		if name == "" {
			name = "default"
		}
		secrets = append(secrets, secretEntry{name: name, secret: settings.Secret})
	}
	if len(secrets) == 0 {
		return instance{}, false
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].name < secrets[j].name })
	return instance{id: inbound.Id, listen: strings.Trim(inbound.Listen, "[]"), port: inbound.Port, secrets: secrets}, true
}

func renderConfig(inst instance, apiPort int, token string) string {
	listen := inst.listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	content := fmt.Sprintf("bind-to = %q\napi-bind-to = %q\napi-token = %q\n\n[secrets]\n", net.JoinHostPort(listen, strconv.Itoa(inst.port)), net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort)), token)
	for _, secret := range inst.secrets {
		content += fmt.Sprintf("%q = %q\n", secret.name, secret.secret)
	}
	return content
}

func writeConfig(inst instance, apiPort int, token string) error {
	if err := os.MkdirAll(configDir(), 0o750); err != nil {
		return err
	}
	return os.WriteFile(configPath(inst.id), []byte(renderConfig(inst, apiPort, token)), 0o600)
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
			m.collectBeforeStop(id)
			if err := proc.Stop(); err != nil {
				logger.Warning("mtproto stop failed:", err)
				continue
			}
			delete(m.procs, id)
			delete(m.ports, id)
			delete(m.last, id)
			delete(m.state, id)
			delete(m.tokens, id)
			_ = os.Remove(configPath(id))
		}
	}
	for id, inst := range wanted {
		fingerprint := renderConfig(inst, 0, "")
		if proc := m.procs[id]; proc != nil && proc.Running() && m.state[id] == fingerprint {
			continue
		}
		if proc := m.procs[id]; proc != nil {
			m.collectBeforeStop(id)
			if err := proc.Stop(); err != nil {
				logger.Warning("mtproto restart failed:", err)
				continue
			}
		}
		apiPort, err := freePort()
		if err != nil {
			logger.Warning("mtproto api port failed:", err)
			continue
		}
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			logger.Warning("mtproto API token failed:", err)
			continue
		}
		token := hex.EncodeToString(buf)
		if err := writeConfig(inst, apiPort, token); err != nil {
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
		m.state[id] = fingerprint
		m.tokens[id] = token
	}
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, proc := range m.procs {
		if err := proc.Stop(); err != nil {
			logger.Warning("mtproto stop failed:", err)
			continue
		}
		_ = os.Remove(configPath(id))
	}
	m.procs = map[int]*Process{}
	m.ports = map[int]int{}
	m.last = map[int]map[string]statsCounter{}
	m.state = map[int]string{}
	m.tokens = map[int]string{}
	m.pending = nil
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
	// cron can start another run while an endpoint is slow. Serialize polls so
	// the same cumulative counters can never be credited twice.
	m.poll.Lock()
	defer m.poll.Unlock()
	type snapshot struct {
		id    int
		port  int
		token string
		proc  *Process
	}
	m.mu.Lock()
	snapshots := make([]snapshot, 0, len(m.ports))
	for id, port := range m.ports {
		snapshots = append(snapshots, snapshot{id, port, m.tokens[id], m.procs[id]})
	}
	traffic := m.pending
	m.pending = nil
	m.mu.Unlock()
	for _, snap := range snapshots {
		users, ok := scrapeStats(snap.port, snap.token)
		if !ok {
			continue
		}
		m.mu.Lock()
		// A slow response belonging to a deleted/restarted instance cannot
		// replace the new instance's baseline or resurrect its counters.
		if m.procs[snap.id] == snap.proc && m.ports[snap.id] == snap.port {
			traffic = append(traffic, trafficDelta(snap.id, m.last[snap.id], users)...)
			m.last[snap.id] = users
		}
		m.mu.Unlock()
	}
	return traffic
}

// RetryTraffic preserves an already scraped interval when SQLite could not
// commit it. The next poll combines this interval with newly collected bytes.
func (m *Manager) RetryTraffic(traffic []*xray.ClientTraffic) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending = append(m.pending, traffic...)
}

// Called under m.mu before replacing a process, preserving the last partial
// sampling interval instead of dropping it whenever a client is edited.
func (m *Manager) collectBeforeStop(id int) {
	if users, ok := scrapeStats(m.ports[id], m.tokens[id]); ok {
		m.pending = append(m.pending, trafficDelta(id, m.last[id], users)...)
		m.last[id] = users
	}
}

func trafficDelta(id int, previous, users map[string]statsCounter) []*xray.ClientTraffic {
	traffic := make([]*xray.ClientTraffic, 0, len(users))
	for email, current := range users {
		old := previous[email]
		up, down := current.Up-old.Up, current.Down-old.Down
		if up < 0 {
			up = 0
		}
		if down < 0 {
			down = 0
		}
		if up > 0 || down > 0 {
			traffic = append(traffic, &xray.ClientTraffic{InboundId: id, Email: email, Up: up, Down: down})
		}
	}
	return traffic
}

func scrapeStats(port int, token string) (map[string]statsCounter, bool) {
	if port == 0 {
		return nil, false
	}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/stats", nil)
	if err != nil {
		return nil, false
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var parsed statsResponse
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&parsed) != nil || parsed.Users == nil {
		return nil, false
	}
	users := make(map[string]statsCounter, len(parsed.Users))
	for email, user := range parsed.Users {
		if user.BytesIn < 0 || user.BytesOut < 0 {
			continue
		}
		users[email] = statsCounter{Up: user.BytesIn, Down: user.BytesOut}
	}
	return users, true
}
