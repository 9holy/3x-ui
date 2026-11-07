package tuic

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"x-ui/config"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/xray"
)

const Protocol model.Protocol = "tuic"

type instance struct {
	id     int
	config []byte
	digest string
}

type Manager struct {
	mu    sync.Mutex
	procs map[int]*Process
	state map[int]string
}

var singleton = &Manager{procs: map[int]*Process{}, state: map[int]string{}}
var errNoActiveUsers = errors.New("TUIC has no active users")

func GetManager() *Manager     { return singleton }
func configDir() string        { return filepath.Join(config.GetBinFolderPath(), "tuic") }
func configPath(id int) string { return filepath.Join(configDir(), fmt.Sprintf("tuic-%d.json", id)) }
func binaryPath() string {
	name := fmt.Sprintf("tuic-server-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(config.GetBinFolderPath(), name)
}

type clientSettings struct {
	ID         string `json:"id"`
	UUID       string `json:"uuid"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	Enable     *bool  `json:"enable"`
	TotalGB    int64  `json:"totalGB"`
	ExpiryTime int64  `json:"expiryTime"`
}

func normalizeUUID(value string) (string, error) {
	value = strings.ToLower(strings.ReplaceAll(value, "-", ""))
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return "", fmt.Errorf("TUIC requires a valid UUID")
	}
	return value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:], nil
}

// NativeConfig adapts panel client records and the upstream flat/nested server
// settings to the pinned tuic-server 1.0.0 schema. That binary rejects unknown
// fields, so panel-only metadata must never reach its configuration file.
func NativeConfig(inbound *model.Inbound, activeOnly bool) ([]byte, error) {
	if inbound.Total > 0 {
		return nil, fmt.Errorf("TUIC sidecar traffic metering is unavailable; inbound total must be 0")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(inbound.Settings), &root); err != nil || root == nil {
		return nil, fmt.Errorf("TUIC settings must be a JSON object")
	}
	settings := make(map[string]json.RawMessage, len(root))
	if raw := root["server"]; len(raw) > 0 && raw[0] == '{' {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(raw, &nested); err != nil {
			return nil, err
		}
		for key, value := range nested {
			settings[key] = value
		}
	}
	// Nested upstream server settings are the base; explicitly supplied flat
	// panel settings override them, matching client links and subscriptions.
	for key, value := range root {
		settings[key] = value
	}
	listen := inbound.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	if net.ParseIP(strings.Trim(listen, "[]")) == nil {
		return nil, fmt.Errorf("TUIC listen must be an IP address")
	}
	if inbound.Port < 1 || inbound.Port > 65535 {
		return nil, fmt.Errorf("invalid TUIC port")
	}
	output := map[string]interface{}{"server": net.JoinHostPort(strings.Trim(listen, "[]"), strconv.Itoa(inbound.Port))}
	// Only these fields exist in the pinned Rust server's deny_unknown_fields
	// Config. SNI, skip-cert-verify and udp_relay_mode belong to client exports.
	keys := []string{"certificate", "private_key", "congestion_control", "alpn", "udp_relay_ipv6", "zero_rtt_handshake", "dual_stack", "max_external_packet_size", "send_window", "receive_window", "log_level"}
	for _, key := range keys {
		if value, ok := settings[key]; ok && string(value) != "null" {
			output[key] = value
		}
	}
	for _, key := range []string{"udp_relay_ipv6", "zero_rtt_handshake", "dual_stack"} {
		if raw := settings[key]; len(raw) > 0 && string(raw) != "null" {
			var value bool
			if err := json.Unmarshal(raw, &value); err != nil {
				return nil, fmt.Errorf("TUIC %s must be a boolean", key)
			}
			output[key] = value
		}
	}
	if raw := settings["alpn"]; len(raw) > 0 && string(raw) != "null" {
		var alpn []string
		if err := json.Unmarshal(raw, &alpn); err != nil {
			return nil, fmt.Errorf("TUIC alpn must be an array of strings")
		}
		for _, value := range alpn {
			if len(value) == 0 || len(value) > 255 {
				return nil, fmt.Errorf("invalid TUIC ALPN token")
			}
		}
		output["alpn"] = alpn
	}
	if raw := settings["log_level"]; len(raw) > 0 && string(raw) != "null" {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("invalid TUIC log_level")
		}
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "warning" {
			value = "warn"
		}
		switch value {
		case "off", "error", "warn", "info", "debug", "trace":
		default:
			return nil, fmt.Errorf("invalid TUIC log_level")
		}
		output["log_level"] = value
	}
	for _, key := range []string{"certificate", "private_key"} {
		var value string
		if json.Unmarshal(settings[key], &value) != nil || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("TUIC requires %s file path", key)
		}
		output[key] = value
	}
	if _, ok := output["alpn"]; !ok {
		output["alpn"] = []string{"h3"}
	}
	if raw := settings["congestion_control"]; len(raw) > 0 {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return nil, fmt.Errorf("invalid TUIC congestion_control")
		}
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "newreno" || value == "new-reno" {
			value = "new_reno"
		}
		if value != "bbr" && value != "cubic" && value != "new_reno" {
			return nil, fmt.Errorf("invalid TUIC congestion_control %q", value)
		}
		output["congestion_control"] = value
	} else {
		output["congestion_control"] = "bbr"
	}
	if _, ok := settings["auth_timeout"]; !ok {
		settings["auth_timeout"] = settings["authentication_timeout"]
	}
	if _, ok := output["max_external_packet_size"]; !ok {
		if raw := settings["max_udp_relay_packet_size"]; len(raw) > 0 && string(raw) != "null" {
			output["max_external_packet_size"] = raw
		}
	}
	for _, key := range []string{"max_external_packet_size", "send_window", "receive_window"} {
		if raw, exists := output[key].(json.RawMessage); exists {
			var value uint64
			if err := json.Unmarshal(raw, &value); err != nil || value == 0 {
				return nil, fmt.Errorf("TUIC %s must be a positive integer", key)
			}
			if key == "max_external_packet_size" {
				if value > 65507 {
					return nil, fmt.Errorf("TUIC max packet size exceeds UDP limits")
				}
				if value > 65245 {
					value = 65245
				}
			}
			if key == "receive_window" && value > 1<<32-1 {
				return nil, fmt.Errorf("TUIC receive_window exceeds uint32")
			}
			output[key] = value
		}
	}
	for _, key := range []string{"auth_timeout", "task_negotiation_timeout", "max_idle_time", "gc_interval", "gc_lifetime"} {
		raw := settings[key]
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil {
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 {
				return nil, fmt.Errorf("invalid TUIC %s duration", key)
			}
		} else {
			var seconds int64
			if json.Unmarshal(raw, &seconds) != nil || seconds <= 0 || seconds > 86400 {
				return nil, fmt.Errorf("invalid TUIC %s seconds", key)
			}
			value = strconv.FormatInt(seconds, 10) + "s"
		}
		output[key] = value
	}
	users := map[string]string{}
	if raw, hasClients := root["clients"]; hasClients {
		var clients []clientSettings
		if json.Unmarshal(raw, &clients) != nil {
			return nil, fmt.Errorf("invalid TUIC clients")
		}
		stats := map[string]xray.ClientTraffic{}
		for _, stat := range inbound.ClientStats {
			stats[stat.Email] = stat
		}
		seen := map[string]bool{}
		emails := map[string]bool{}
		for _, client := range clients {
			if client.TotalGB > 0 {
				return nil, fmt.Errorf("TUIC sidecar traffic metering is unavailable; client totalGB must be 0")
			}
			if client.ExpiryTime < 0 {
				return nil, fmt.Errorf("TUIC sidecar cannot detect first use; use an absolute client expiry time instead of delayed start")
			}
			// The panel edits id. An imported legacy uuid must not override a
			// rotated canonical credential if both fields are still present.
			id := client.ID
			if id == "" {
				id = client.UUID
			}
			id, err := normalizeUUID(id)
			if err != nil {
				return nil, err
			}
			if client.Email == "" || emails[client.Email] {
				return nil, fmt.Errorf("TUIC client email must be non-empty and unique")
			}
			if client.Password == "" || seen[id] {
				return nil, fmt.Errorf("TUIC clients require unique UUIDs and non-empty passwords")
			}
			seen[id], emails[client.Email] = true, true
			if activeOnly {
				if (client.Enable != nil && !*client.Enable) || (client.ExpiryTime > 0 && client.ExpiryTime <= time.Now().UnixMilli()) {
					continue
				}
				if stat, ok := stats[client.Email]; ok && (!stat.Enable || (stat.Total > 0 && stat.Up+stat.Down >= stat.Total) || (stat.ExpiryTime > 0 && stat.ExpiryTime <= time.Now().UnixMilli())) {
					continue
				}
			}
			users[id] = client.Password
		}
	} else {
		var rawUsers map[string]string
		if json.Unmarshal(settings["users"], &rawUsers) != nil {
			return nil, fmt.Errorf("TUIC requires clients or a users map")
		}
		for id, password := range rawUsers {
			normalized, err := normalizeUUID(id)
			if err != nil || password == "" {
				return nil, fmt.Errorf("invalid TUIC user credentials")
			}
			if _, duplicate := users[normalized]; duplicate {
				return nil, fmt.Errorf("duplicate TUIC UUID")
			}
			users[normalized] = password
		}
	}
	if len(users) == 0 {
		return nil, errNoActiveUsers
	}
	output["users"] = users
	return json.MarshalIndent(output, "", "  ")
}

func ValidateSettings(inbound *model.Inbound) error {
	_, err := NativeConfig(inbound, false)
	if errors.Is(err, errNoActiveUsers) {
		return nil
	}
	if err != nil {
		return err
	}
	if !inbound.Enable {
		return nil
	}
	content, err := NativeConfig(inbound, true)
	if errors.Is(err, errNoActiveUsers) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := os.Stat(binaryPath()); err != nil {
		return fmt.Errorf("TUIC runtime is unavailable; install %s: %w", binaryPath(), err)
	}
	var settings struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(content, &settings); err != nil {
		return err
	}
	if _, err := tls.LoadX509KeyPair(settings.Certificate, settings.PrivateKey); err != nil {
		return fmt.Errorf("invalid TUIC TLS certificate/key: %w", err)
	}
	return nil
}

func parseInstance(inbound *model.Inbound) (instance, bool) {
	if inbound == nil || inbound.Protocol != Protocol || !inbound.Enable ||
		(inbound.ExpiryTime > 0 && inbound.ExpiryTime <= time.Now().UnixMilli()) ||
		(inbound.Total > 0 && inbound.Up+inbound.Down >= inbound.Total) {
		return instance{}, false
	}
	content, err := NativeConfig(inbound, true)
	if err != nil {
		if !errors.Is(err, errNoActiveUsers) {
			logger.Warning("tuic config failed:", err)
		}
		return instance{}, false
	}
	hash := sha256.Sum256(content)
	return instance{id: inbound.Id, config: content, digest: hex.EncodeToString(hash[:])}, true
}

func writeConfig(inst instance) error {
	if err := os.MkdirAll(configDir(), 0o750); err != nil {
		return err
	}
	return os.WriteFile(configPath(inst.id), inst.config, 0o600)
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
			if err := proc.Stop(); err != nil {
				logger.Warning("tuic stop failed:", err)
				continue
			}
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
			if err := proc.Stop(); err != nil {
				logger.Warning("tuic restart failed:", err)
				continue
			}
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
		m.procs[id], m.state[id] = proc, inst.digest
	}
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, proc := range m.procs {
		if err := proc.Stop(); err != nil {
			logger.Warning("tuic stop failed:", err)
			continue
		}
		_ = os.Remove(configPath(id))
		delete(m.procs, id)
		delete(m.state, id)
	}
}
