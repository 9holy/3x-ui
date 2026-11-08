package service

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"x-ui/xray"
)

func TestCoreVersionsAndARMArchiveNames(t *testing.T) {
	for _, version := range []string{"v1.8.24", "v26.9.9", "v26.10.30", "v26.10.31-rc", "../../x"} {
		if supportedCoreVersion(version) {
			t.Errorf("unsupported version accepted: %s", version)
		}
	}
	for _, version := range []string{"26.10.31", "v26.11.1", "v27.1.1"} {
		if !supportedCoreVersion(version) {
			t.Errorf("rejected %s", version)
		}
	}
	for goarm, suffix := range map[string]string{"5": "v5", "6,softfloat": "v6", "7,hardfloat": "v7a"} {
		got, err := coreArchiveName("arm", goarm)
		if err != nil || got != "Xray-linux-arm32-"+suffix+".zip" {
			t.Fatalf("%s: %s %v", goarm, got, err)
		}
	}
	if _, err := coreArchiveName("arm", ""); err == nil {
		t.Fatal("unknown ARM ISA silently selected")
	}
}

func TestCoreCandidateStartupFailureRestoresBinaryAndProcess(t *testing.T) {
	protocolDB(t)
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	old := "#!/bin/sh\ncase \"$1\" in version|-version) echo 'Xray 26.10.31';; run) exit 0;; *) trap 'exit 0' TERM; while :; do sleep 0.05; done;; esac\n"
	if err := os.WriteFile(xray.GetBinaryPath(), []byte(old), 0755); err != nil {
		t.Fatal(err)
	}
	previous := xray.NewProcess(&xray.Config{})
	if err := previous.Start(); err != nil {
		t.Fatal(err)
	}
	processMu.Lock()
	p = previous
	processMu.Unlock()
	t.Cleanup(func() {
		if previous.IsRunning() {
			_ = previous.Stop()
		}
	})
	candidate := filepath.Join(dir, "candidate")
	broken := "#!/bin/sh\ncase \"$1\" in version|-version) echo 'Xray 26.11.1';; run) exit 0;; *) exit 23;; esac\n"
	if err := os.WriteFile(candidate, []byte(broken), 0755); err != nil {
		t.Fatal(err)
	}
	if err := (&ServerService{}).installCoreCandidate(candidate, "v26.11.1"); err == nil {
		t.Fatal("failed startup reported success")
	}
	data, err := os.ReadFile(xray.GetBinaryPath())
	if err != nil || string(data) != old {
		t.Fatal("old binary not restored", err)
	}
	if currentXrayProcess() != previous || !previous.IsRunning() {
		t.Fatal("original process not restored")
	}
}

func TestX25519CurrentAndLegacyLabels(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, label := range []string{"Public key", "PublicKey", "Password (PublicKey)", "Password"} {
		pair, err := parseX25519Keys("PrivateKey: " + key + "\n" + label + ": " + key + "\nHash32: unused\n")
		if err != nil || pair["publicKey"] != key || pair["privateKey"] != key {
			t.Fatalf("%s: %v %v", label, pair, err)
		}
	}
	if _, err := parseX25519Keys("PrivateKey: private-secret\n"); err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatal("invalid/private output error", err)
	}
}
