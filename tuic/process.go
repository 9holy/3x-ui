package tuic

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"x-ui/logger"
)

type Process struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	done   chan struct{}
	config string
}

func newProcess(config string) *Process { return &Process{config: config} }

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

func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.runningLocked()
}

func (p *Process) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.runningLocked() {
		return errors.New("tuic is already running")
	}
	if _, err := os.Stat(binaryPath()); err != nil {
		return fmt.Errorf("TUIC runtime is unavailable for %s/%s; install %s: %w", runtime.GOOS, runtime.GOARCH, binaryPath(), err)
	}
	cmd := exec.Command(binaryPath(), "-c", p.config)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tuic-server: %w", err)
	}
	done := make(chan struct{})
	p.cmd, p.done = cmd, done
	go func() {
		defer close(done)
		if err := cmd.Wait(); err != nil {
			logger.Debug("tuic process exited:", err)
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
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
			return nil
		case <-timer.C:
		}
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-done:
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("timed out waiting for tuic-server to exit")
	}
}
