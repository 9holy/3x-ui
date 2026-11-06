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
)

type Process struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	config string
}

func newProcess(config string) *Process { return &Process{config: config} }
func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}
func (p *Process) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil {
		return errors.New("tuic is already running")
	}
	cmd := exec.Command(binaryPath(), "-c", p.config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tuic-server: %w", err)
	}
	p.cmd = cmd
	go cmd.Wait()
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
	for p.Running() {
		select {
		case <-deadline.C:
			return cmd.Process.Kill()
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
	return nil
}
