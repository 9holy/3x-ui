package xray_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"x-ui/xray"
)

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func TestNativeHotAddPreservesXHTTP(t *testing.T) {
	binary := os.Getenv("XUI_TEST_XRAY")
	if binary == "" {
		t.Skip("set XUI_TEST_XRAY to test the native hot-add path")
	}
	dir := t.TempDir()
	if err := os.Symlink(binary, filepath.Join(dir, xray.GetBinaryName())); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XUI_BIN_FOLDER", dir)
	port := freePort(t)
	config := fmt.Sprintf(`{"log":{"loglevel":"warning"},"api":{"tag":"api","services":["HandlerService"]},"inbounds":[{"tag":"api-in","listen":"127.0.0.1","port":%d,"protocol":"tunnel","settings":{"address":"127.0.0.1"}}],"outbounds":[{"protocol":"freedom"}],"routing":{"rules":[{"type":"field","inboundTag":["api-in"],"outboundTag":"api"}]}}`, port)
	path := filepath.Join(dir, "core.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	address := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("test Xray API did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	api := &xray.XrayAPI{}
	if err := api.Init(port); err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	inbound := fmt.Sprintf(`{"tag":"audit-xhttp","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[{"id":"11111111-1111-4111-8111-111111111111","email":"audit"}],"decryption":"none"},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/audit-path","mode":"packet-up","xPaddingBytes":"200-300"}}}`, freePort(t))
	if err := xray.ValidateInboundConfig([]byte(inbound)); err != nil {
		t.Fatal(err)
	}
	if err := api.AddInbound([]byte(inbound)); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(binary, "api", "lsi", "--server="+address, "--isOnlyTags=false").CombinedOutput()
	if err != nil {
		t.Fatalf("list inbounds: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "audit-xhttp") || !strings.Contains(string(output), "/audit-path") || !strings.Contains(string(output), `"from": 200`) || !strings.Contains(string(output), `"to": 300`) {
		t.Fatalf("hot-add dropped modern transport fields: %s", output)
	}
	var invalid map[string]interface{}
	_ = json.Unmarshal([]byte(inbound), &invalid)
	invalid["protocol"] = "not-a-protocol"
	bad, _ := json.Marshal(invalid)
	if err := xray.ValidateInboundConfig(bad); err == nil {
		t.Fatal("native validator accepted an invalid protocol")
	}
}
