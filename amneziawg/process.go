package amneziawg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"x-ui/config"
)

// awg-quick is a one-shot interface setup command, not the interface's daemon.
// A successful "up" therefore remains active after that command exits.
type Process struct {
	mu              sync.Mutex
	ifName          string
	config          string
	signature       string
	active          bool
	interfaceExists func(string) bool
}

func newProcess(ifName, configPath, signature string) *Process {
	return &Process{ifName: ifName, config: configPath, signature: signature, interfaceExists: interfaceExists}
}

func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func (p *Process) ConfigPath() string { return p.config }
func (p *Process) Signature() string  { return p.signature }

func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active && p.interfaceExists(p.ifName)
}

func commandName() string {
	if name := os.Getenv("AMNEZIAWG_QUICK"); name != "" {
		return name
	}
	path := filepath.Join(config.GetBinFolderPath(), "awg-quick")
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		if absolute, err := filepath.Abs(path); err == nil {
			return absolute
		}
	}
	return "awg-quick"
}

func (p *Process) run(action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, commandName(), action, p.config)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	binDir, _ := filepath.Abs(config.GetBinFolderPath())
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	goImpl := os.Getenv("AMNEZIAWG_GO")
	if goImpl == "" {
		candidate := filepath.Join(binDir, "amneziawg-go")
		if _, err := os.Stat(candidate); err == nil {
			goImpl = candidate
		}
	}
	if goImpl != "" {
		cmd.Env = append(cmd.Env, "WG_QUICK_USERSPACE_IMPLEMENTATION="+goImpl)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("awg-quick %s %s: %w", action, p.ifName, err)
	}
	return nil
}

func (p *Process) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.interfaceExists(p.ifName) {
		return fmt.Errorf("AmneziaWG interface %q already exists", p.ifName)
	}
	if err := p.run("up"); err != nil {
		return err
	}
	p.active = true
	if !p.interfaceExists(p.ifName) {
		p.active = false
		return fmt.Errorf("awg-quick returned success but interface %q was not created", p.ifName)
	}
	return nil
}

func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active {
		return nil
	}
	if !p.interfaceExists(p.ifName) {
		p.active = false
		return nil
	}
	if err := p.run("down"); err != nil {
		return err
	}
	if p.interfaceExists(p.ifName) {
		return errors.New("awg-quick returned success but the interface is still present")
	}
	p.active = false
	return nil
}
