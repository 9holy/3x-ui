package mtproto

import (
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
)

type Process struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	config string
}

func binaryPath() string {
	name := "mtg"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return config.GetBinFolderPath() + "/" + name
}

func newProcess(configPath string) *Process {
	return &Process{config: configPath}
}

func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

func (p *Process) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil {
		return errors.New("mtg is already running")
	}
	cmd := exec.Command(binaryPath(), "run", p.config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start mtg: %w", err)
	}
	p.cmd = cmd
	go func() {
		if err := cmd.Wait(); err != nil {
			logger.Warning("mtproto process exited:", err)
		}
	}()
	return nil
}

func (p *Process) Stop() error {
	p.mu.Lock()
	cmd := p.cmd
	p.mu.Unlock()
	if cmd == nil || cmd.Process == nil || cmd.ProcessState != nil {
		return nil
	}
	if runtime.GOOS == "windows" {
		return cmd.Process.Kill()
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		if !p.Running() {
			return nil
		}
		select {
		case <-deadline.C:
			return cmd.Process.Kill()
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
}
