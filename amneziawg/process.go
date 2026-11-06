package amneziawg

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Process struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	ifName string
	config string
}

func newProcess(ifName, config string) *Process {
	return &Process{ifName: ifName, config: config}
}

func (p *Process) ConfigPath() string { return p.config }

func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

func (p *Process) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil {
		return errors.New("amneziawg is already running")
	}
	quick := os.Getenv("AMNEZIAWG_QUICK")
	if quick == "" {
		quick = "awg-quick"
	}
	cmd := exec.Command(quick, "up", p.config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if goImpl := os.Getenv("AMNEZIAWG_GO"); goImpl != "" {
		cmd.Env = append(os.Environ(), "WG_QUICK_USERSPACE_IMPLEMENTATION="+goImpl)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", quick, err)
	}
	p.cmd = cmd
	go func() { _ = cmd.Wait() }()
	return nil
}

func (p *Process) Stop() error {
	p.mu.Lock()
	cmd := p.cmd
	p.mu.Unlock()
	if cmd == nil || cmd.Process == nil || cmd.ProcessState != nil {
		return nil
	}
	quick := os.Getenv("AMNEZIAWG_QUICK")
	if quick == "" {
		quick = "awg-quick"
	}
	down := exec.Command(quick, "down", p.config)
	down.Stdout = os.Stdout
	down.Stderr = os.Stderr
	if err := down.Run(); err == nil {
		return nil
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

func commandName() string {
	name := os.Getenv("AMNEZIAWG_QUICK")
	if strings.TrimSpace(name) == "" {
		return "awg-quick"
	}
	return name
}
