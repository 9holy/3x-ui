package amneziawg

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"x-ui/config"
	"x-ui/database/model"
	"x-ui/logger"
)

const Protocol model.Protocol = "amneziawg"

type desired struct {
	id     int
	ifName string
	config string
	digest string
}

type Manager struct {
	mu    sync.Mutex
	procs map[int]*Process
}

var singleton = &Manager{procs: map[int]*Process{}}

func GetManager() *Manager { return singleton }

func configDir() string { return filepath.Join(config.GetBinFolderPath(), "amneziawg") }
func configPath(id int, ifName string) string {
	// awg-quick derives the interface name from the .conf basename.
	return filepath.Join(configDir(), fmt.Sprint(id), ifName+".conf")
}

var interfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)

func parseDesired(inbound *model.Inbound) (desired, error) {
	if inbound.Total > 0 {
		return desired{}, fmt.Errorf("AmneziaWG raw-config traffic metering is unavailable; inbound total must be 0")
	}
	var settings struct {
		Interface  string            `json:"interface"`
		Config     string            `json:"config"`
		ConfigPath string            `json:"configPath"`
		Clients    []json.RawMessage `json:"clients"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return desired{}, fmt.Errorf("invalid AmneziaWG settings: %w", err)
	}
	if len(settings.Clients) > 0 {
		return desired{}, fmt.Errorf("AmneziaWG peers must be edited in config; panel clients are not mapped to native peers")
	}
	if settings.Config == "" && settings.ConfigPath == "" {
		return desired{}, fmt.Errorf("AmneziaWG requires config or configPath")
	}
	configText := settings.Config
	if settings.ConfigPath != "" {
		content, err := os.ReadFile(settings.ConfigPath)
		if err != nil {
			return desired{}, fmt.Errorf("read AmneziaWG config: %w", err)
		}
		configText = string(content)
		if settings.Interface == "" {
			settings.Interface = strings.TrimSuffix(filepath.Base(settings.ConfigPath), ".conf")
		}
	}
	if settings.Interface == "" {
		settings.Interface = fmt.Sprintf("awg%d", inbound.Id)
	}
	if !interfaceNamePattern.MatchString(settings.Interface) || settings.Interface == "." || settings.Interface == ".." {
		return desired{}, fmt.Errorf("invalid AmneziaWG interface name %q", settings.Interface)
	}
	normalized, err := normalizeConfig(configText, inbound.Port)
	if err != nil {
		return desired{}, err
	}
	hash := sha256.Sum256([]byte(settings.Interface + "\x00" + normalized))
	return desired{id: inbound.Id, ifName: settings.Interface, config: normalized, digest: hex.EncodeToString(hash[:])}, nil
}

func ValidateSettings(inbound *model.Inbound) error {
	_, err := parseDesired(inbound)
	if err != nil {
		return err
	}
	if inbound.Enable {
		if _, err := exec.LookPath(commandName()); err != nil {
			return fmt.Errorf("AmneziaWG runtime is unavailable: %w", err)
		}
	}
	return nil
}

// ListenPort belongs to the panel's inbound; allowing a different value in raw
// config would defeat port-conflict checks and make exported endpoints wrong.
func normalizeConfig(raw string, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid AmneziaWG port")
	}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	result := make([]string, 0, len(lines)+1)
	inInterface, foundInterface, foundPrivateKey := false, false, false
	for _, line := range lines {
		trimmed := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inInterface = strings.EqualFold(trimmed, "[Interface]")
			if inInterface {
				if foundInterface {
					return "", fmt.Errorf("AmneziaWG config has duplicate [Interface] sections")
				}
				foundInterface = true
				result = append(result, line, fmt.Sprintf("ListenPort = %d", port))
				continue
			}
		}
		if inInterface {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				if strings.EqualFold(key, "ListenPort") {
					continue
				}
				if strings.EqualFold(key, "PrivateKey") {
					decoded, err := base64.StdEncoding.DecodeString(value)
					if err != nil || len(decoded) != 32 {
						return "", fmt.Errorf("AmneziaWG PrivateKey must encode 32 bytes")
					}
					foundPrivateKey = true
				}
				// SaveConfig would rewrite our managed snapshot during down,
				// making subsequent reconciliation appear to change the config.
				if strings.EqualFold(key, "SaveConfig") && strings.EqualFold(value, "true") {
					return "", fmt.Errorf("AmneziaWG managed config does not support SaveConfig=true")
				}
			}
		}
		result = append(result, line)
	}
	if !foundInterface || !foundPrivateKey {
		return "", fmt.Errorf("AmneziaWG requires [Interface] with a PrivateKey")
	}
	return strings.Join(result, "\n"), nil
}

func (m *Manager) Reconcile(inbounds []*model.Inbound) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wanted := make(map[int]desired)
	for _, inbound := range inbounds {
		if inbound == nil || inbound.Protocol != Protocol || !inbound.Enable ||
			(inbound.ExpiryTime > 0 && inbound.ExpiryTime <= time.Now().UnixMilli()) ||
			(inbound.Total > 0 && inbound.Up+inbound.Down >= inbound.Total) {
			continue
		}
		item, err := parseDesired(inbound)
		if err != nil {
			logger.Warning("amneziawg config failed:", err)
			continue
		}
		wanted[item.id] = item
	}
	for id, proc := range m.procs {
		if _, ok := wanted[id]; !ok {
			if err := proc.Stop(); err != nil {
				logger.Warning("amneziawg stop failed:", err)
				continue
			}
			delete(m.procs, id)
			_ = os.Remove(proc.ConfigPath())
		}
	}
	for id, item := range wanted {
		if proc := m.procs[id]; proc != nil && proc.Running() && proc.Signature() == item.digest {
			continue
		}
		if proc := m.procs[id]; proc != nil {
			if err := proc.Stop(); err != nil {
				logger.Warning("amneziawg restart failed:", err)
				continue
			}
			_ = os.Remove(proc.ConfigPath())
			delete(m.procs, id)
		}
		path, err := writeConfig(item)
		if err != nil {
			logger.Warning("amneziawg config failed:", err)
			continue
		}
		proc := newProcess(item.ifName, path, item.digest)
		if err := proc.Start(); err != nil {
			logger.Warning("amneziawg start failed:", err)
			continue
		}
		m.procs[id] = proc
	}
}

func writeConfig(item desired) (string, error) {
	path, err := filepath.Abs(configPath(item.id, item.ifName))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(item.config), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, proc := range m.procs {
		if err := proc.Stop(); err != nil {
			logger.Warning("amneziawg stop failed:", err)
			continue
		}
		_ = os.Remove(proc.ConfigPath())
		delete(m.procs, id)
	}
}
