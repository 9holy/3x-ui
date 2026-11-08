package xray

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"x-ui/config"
	"x-ui/logger"
	"x-ui/util/common"
)

func GetBinaryName() string {
	return fmt.Sprintf("xray-%s-%s", runtime.GOOS, runtime.GOARCH)
}

func GetBinaryPath() string {
	return config.GetBinFolderPath() + "/" + GetBinaryName()
}

func GetConfigPath() string {
	return config.GetBinFolderPath() + "/config.json"
}

func GetGeositePath() string {
	return config.GetBinFolderPath() + "/geosite.dat"
}

func GetGeoipPath() string {
	return config.GetBinFolderPath() + "/geoip.dat"
}

func GetIPLimitLogPath() string {
	return config.GetLogFolder() + "/3xipl.log"
}

func GetIPLimitBannedLogPath() string {
	return config.GetLogFolder() + "/3xipl-banned.log"
}

func GetIPLimitBannedPrevLogPath() string {
	return config.GetLogFolder() + "/3xipl-banned.prev.log"
}

func GetAccessPersistentLogPath() string {
	return config.GetLogFolder() + "/3xipl-ap.log"
}

func GetAccessPersistentPrevLogPath() string {
	return config.GetLogFolder() + "/3xipl-ap.prev.log"
}

func GetAccessLogPath() (string, error) {
	config, err := os.ReadFile(GetConfigPath())
	if err != nil {
		logger.Warningf("Failed to read configuration file: %s", err)
		return "", err
	}

	jsonConfig := map[string]interface{}{}
	err = json.Unmarshal([]byte(config), &jsonConfig)
	if err != nil {
		logger.Warningf("Failed to parse JSON configuration: %s", err)
		return "", err
	}

	if jsonConfig["log"] != nil {
		jsonLog := jsonConfig["log"].(map[string]interface{})
		if jsonLog["access"] != nil {
			accessLogPath := jsonLog["access"].(string)
			return accessLogPath, nil
		}
	}
	return "", err
}

func stopProcess(p *Process) {
	p.Stop()
}

type Process struct {
	*process
}

func NewProcess(xrayConfig *Config) *Process {
	p := &Process{newProcess(xrayConfig)}
	runtime.SetFinalizer(p, stopProcess)
	return p
}

type process struct {
	mu        sync.RWMutex
	lifecycle sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	running   bool
	stopping  bool

	version string
	apiPort int

	onlineClients []string

	config    *Config
	logWriter *LogWriter
	exitErr   error
	startTime time.Time
}

func newProcess(config *Config) *process {
	return &process{
		version:   "Unknown",
		config:    config,
		logWriter: NewLogWriter(),
		startTime: time.Now(),
	}
}

func (p *process) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

func (p *process) GetErr() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.exitErr
}

func (p *process) GetResult() string {
	line := p.logWriter.LastLine()
	if err := p.GetErr(); line == "" && err != nil {
		return err.Error()
	}
	return line
}

func (p *process) GetVersion() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version
}

func (p *Process) GetAPIPort() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.apiPort
}

func (p *Process) GetConfig() *Config {
	return p.config
}

func (p *Process) GetOnlineClients() []string {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.onlineClients...)
}

func (p *Process) SetOnlineClients(users []string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onlineClients = append([]string(nil), users...)
}

func (p *Process) GetUptime() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return uint64(time.Since(p.startTime).Seconds())
}

func (p *process) refreshAPIPort() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, inbound := range p.config.InboundConfigs {
		if inbound.Tag == "api" {
			p.apiPort = inbound.Port
			break
		}
	}
}

func (p *process) refreshVersion() {
	cmd := exec.Command(GetBinaryPath(), "-version")
	data, err := cmd.Output()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.version = "Unknown"
	} else {
		datas := bytes.Split(data, []byte(" "))
		if len(datas) <= 1 {
			p.version = "Unknown"
		} else {
			p.version = string(datas[1])
		}
	}
}

func (p *process) Start() (err error) {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	if p.IsRunning() {
		return errors.New("xray is already running")
	}

	defer func() {
		if err != nil {
			logger.Error("Failure in running xray-core process: ", err)
			p.mu.Lock()
			p.exitErr = err
			p.mu.Unlock()
		}
	}()

	data, err := json.MarshalIndent(p.config, "", "  ")
	if err != nil {
		return common.NewErrorf("Failed to generate XRAY configuration files: %v", err)
	}

	err = os.MkdirAll(config.GetLogFolder(), 0o770)
	if err != nil {
		logger.Warningf("Failed to create log folder: %s", err)
	}

	configPath := GetConfigPath()
	err = os.WriteFile(configPath, data, 0600)
	if err != nil {
		return common.NewErrorf("Failed to write configuration file: %v", err)
	}
	if err = os.Chmod(configPath, 0600); err != nil {
		return err
	}

	cmd := exec.Command(GetBinaryPath(), "-c", configPath)

	cmd.Stdout = p.logWriter
	cmd.Stderr = p.logWriter

	p.refreshVersion()
	p.refreshAPIPort()
	if err = cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	p.mu.Lock()
	p.cmd, p.done, p.running, p.stopping = cmd, done, true, false
	p.exitErr, p.startTime = nil, time.Now()
	p.mu.Unlock()
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		if err != nil && !p.stopping {
			p.exitErr = err
		}
		p.running = false
		close(done)
		p.mu.Unlock()
	}()
	select {
	case <-done:
		if err := p.GetErr(); err != nil {
			return err
		}
		return errors.New("xray exited during startup")
	case <-time.After(100 * time.Millisecond):
	}

	return nil
}

func (p *process) Stop() error {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return errors.New("xray is not running")
	}
	cmd, done := p.cmd, p.done
	p.stopping = true
	p.mu.Unlock()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		<-done
		return nil
	}
}
