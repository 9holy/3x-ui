package amneziawg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"x-ui/database/model"
)

const nativeConfig = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.1/24\nListenPort = 1111\n"

func TestQuickProcessRemainsActiveAfterUpCommandExitsAndRunsDown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux quick interface fixture")
	}
	dir := t.TempDir()
	marker, log := filepath.Join(dir, "interface"), filepath.Join(dir, "commands")
	t.Setenv("AWG_TEST_MARKER", marker)
	t.Setenv("AWG_TEST_LOG", log)
	quick := filepath.Join(dir, "awg-quick")
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$AWG_TEST_LOG\"\ncase $1 in\nup) touch \"$AWG_TEST_MARKER\" ;;\ndown) rm \"$AWG_TEST_MARKER\" ;;\nesac\n"
	if err := os.WriteFile(quick, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AMNEZIAWG_QUICK", quick)
	proc := newProcess("awg-test", filepath.Join(dir, "awg-test.conf"), "digest")
	proc.interfaceExists = func(string) bool { _, err := os.Stat(marker); return err == nil }
	t.Cleanup(func() { _ = proc.Stop() })
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	if !proc.Running() {
		t.Fatal("successful one-shot up incorrectly reported stopped")
	}
	if err := proc.Start(); err == nil {
		t.Fatal("duplicate up accepted for an active interface")
	}
	if err := proc.Stop(); err != nil {
		t.Fatal(err)
	}
	if proc.Running() {
		t.Fatal("down did not stop the interface")
	}
	commands, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if string(commands) != "up\ndown\n" {
		t.Fatalf("wrong lifecycle: %q", commands)
	}
}

func TestConfigUsesSelectedInterfaceAndDetectsExternalFileChanges(t *testing.T) {
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())
	settings, _ := json.Marshal(map[string]string{"interface": "vpn-test", "config": nativeConfig})
	inbound := &model.Inbound{Id: 17, Protocol: Protocol, Port: 51820, Settings: string(settings)}
	first, err := parseDesired(inbound)
	if err != nil {
		t.Fatal(err)
	}
	path, err := writeConfig(first)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "vpn-test.conf" {
		t.Fatalf("interface ignored: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ListenPort = 51820") || strings.Contains(string(data), "ListenPort = 1111") {
		t.Fatal("managed inbound port not applied")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("private-key configuration must be owner-only")
	}
	external := filepath.Join(t.TempDir(), "external.conf")
	if err := os.WriteFile(external, []byte(nativeConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, _ = json.Marshal(map[string]string{"configPath": external})
	inbound.Settings = string(settings)
	old, err := parseDesired(inbound)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(external, []byte(nativeConfig+"MTU = 1280\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := parseDesired(inbound)
	if err != nil {
		t.Fatal(err)
	}
	if old.digest == changed.digest {
		t.Fatal("external config changes would not reload")
	}
	if changed.ifName != "external" {
		t.Fatal("external config interface name was ignored")
	}
}

func TestRawAWGRejectsUnmappedClientsAndUnmeteredQuotas(t *testing.T) {
	for _, clientMode := range []bool{false, true} {
		settings := map[string]interface{}{"config": nativeConfig}
		inbound := &model.Inbound{Id: 1, Protocol: Protocol, Port: 51820, Total: 1}
		if clientMode {
			inbound.Total = 0
			settings["clients"] = []map[string]interface{}{{"email": "unmapped"}}
		}
		raw, _ := json.Marshal(settings)
		inbound.Settings = string(raw)
		if err := ValidateSettings(inbound); err == nil {
			t.Fatal("unsupported client/quota operation silently accepted")
		}
	}
}
