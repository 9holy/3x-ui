package mtproto

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	done   chan struct{}
	config string
}

func binaryPath() string {
	name := fmt.Sprintf("mtg-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(config.GetBinFolderPath(), name)
}

func newProcess(configPath string) *Process {
	return &Process{config: configPath}
}

func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.runningLocked()
}

// Wait writes exec.Cmd.ProcessState asynchronously. Use the completion channel
// instead so reconciliation and shutdown do not race with that write.
func (p *Process) runningLocked() bool {
	if p.cmd == nil || p.done == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *Process) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.runningLocked() {
		return errors.New("mtg is already running")
	}
	cmd := exec.Command(binaryPath(), "run", p.config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start mtg: %w", err)
	}
	p.cmd = cmd
	done := make(chan struct{})
	p.done = done
	go func() {
		defer close(done)
		if err := cmd.Wait(); err != nil {
			logger.Debug("mtproto process exited:", err)
		}
	}()
	return nil
}

func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.runningLocked() {
		return nil
	}
	cmd, done := p.cmd, p.done
	if runtime.GOOS != "windows" {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		select {
		case <-done:
			return nil
		case <-deadline.C:
		}
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	// Reap the old process before a replacement tries to bind the same port.
	select {
	case <-done:
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("timed out waiting for mtg to exit")
	}
}
