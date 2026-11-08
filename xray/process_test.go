package xray

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"x-ui/logger"
)

func TestProcessReportsMissingBinarySynchronously(t *testing.T) {
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	p := NewProcess(&Config{})
	if err := p.Start(); err == nil {
		t.Fatal("missing executable reported success")
	}
	if p.IsRunning() || p.GetErr() == nil {
		t.Fatal("failed process has inconsistent status")
	}
}

func TestPackagedProcessConcurrentStatusAndStop(t *testing.T) {
	binary := os.Getenv("XUI_TEST_XRAY")
	if binary == "" {
		t.Skip("set XUI_TEST_XRAY to verify the packaged process")
	}
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	if err := os.Symlink(binary, filepath.Join(dir, GetBinaryName())); err != nil {
		t.Fatal(err)
	}
	p := NewProcess(&Config{})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = p.IsRunning()
				_ = p.GetVersion()
				_ = p.GetResult()
				_ = p.GetUptime()
				_ = p.GetAPIPort()
				p.SetOnlineClients([]string{"client"})
				got := p.GetOnlineClients()
				if len(got) > 0 {
					got[0] = "copy"
				}
				_ = logger.GetLogs(2, "INFO")
			}
		}()
	}
	defer func() {
		close(stop)
		wg.Wait()
		if p.IsRunning() {
			_ = p.Stop()
		}
	}()
	for i := 0; i < 3; i++ {
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		if !p.IsRunning() {
			t.Fatal("started process not running")
		}
		if err := p.Stop(); err != nil {
			t.Fatal(err)
		}
		if p.IsRunning() {
			t.Fatal("Stop returned before process exited")
		}
	}
	info, err := os.Stat(GetConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions %o", info.Mode().Perm())
	}
}
