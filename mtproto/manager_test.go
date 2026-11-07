package mtproto

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"x-ui/database/model"
	"x-ui/xray"

	"github.com/pelletier/go-toml/v2"
)

const testSecret = "ee0123456789abcdef0123456789abcdef6578616d706c652e636f6d"

func TestEffectiveClientsExcludeDisabledExpiredAndDepleted(t *testing.T) {
	inbound := &model.Inbound{Id: 1, Protocol: Protocol, Enable: true, Port: 443}
	inbound.Settings = fmt.Sprintf(`{"secret":%q,"clients":[{"email":"active","secret":%q},{"email":"disabled","secret":%q,"enable":false},{"email":"expired","secret":%q,"expiryTime":1},{"email":"depleted","secret":%q}]}`, testSecret, testSecret, testSecret, testSecret, testSecret)
	inbound.ClientStats = []xray.ClientTraffic{{Email: "depleted", Enable: false}}
	inst, ok := parseInstance(inbound)
	if !ok || len(inst.secrets) != 1 || inst.secrets[0].name != "active" {
		t.Fatalf("effective secrets: %+v, %v", inst.secrets, ok)
	}
	inbound.Settings = fmt.Sprintf(`{"secret":%q,"clients":[]}`, testSecret)
	if _, ok := parseInstance(inbound); ok {
		t.Fatal("legacy secret resurrected an explicitly empty client list")
	}
	inbound.Settings = fmt.Sprintf(`{"clients":[{"email":"active","secret":%q}]}`, testSecret)
	inbound.ClientStats = []xray.ClientTraffic{{Email: "active", Enable: true, Total: 10, Up: 10}}
	if _, ok := parseInstance(inbound); ok {
		t.Fatal("quota-depleted client is still served")
	}
}

func TestGeneratedConfigUsesIPv6EndpointAndAuthenticatedAPI(t *testing.T) {
	inst := instance{id: 1, listen: "::1", port: 443, secrets: []secretEntry{{name: "test.user", secret: testSecret}}}
	var parsed map[string]interface{}
	if err := toml.Unmarshal([]byte(renderConfig(inst, 23456, "token")), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["bind-to"] != "[::1]:443" || parsed["api-token"] != "token" {
		t.Fatalf("bad endpoints/auth: %+v", parsed)
	}
}

func TestReconcileRestartsOnCredentialAndPortChanges(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell process fixture")
	}
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())
	if err := os.WriteFile(binaryPath(), []byte("#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 0.05; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	mgr := newManager()
	t.Cleanup(mgr.StopAll)
	inbound := &model.Inbound{Id: 3, Protocol: Protocol, Enable: true, Port: 12345, Settings: fmt.Sprintf(`{"clients":[{"email":"test","secret":%q}]}`, testSecret)}
	mgr.Reconcile([]*model.Inbound{inbound})
	first := mgr.procs[3]
	if first == nil || !first.Running() {
		t.Fatal("first process did not start")
	}
	mgr.Reconcile([]*model.Inbound{inbound})
	if mgr.procs[3] != first {
		t.Fatal("unchanged config restarted")
	}
	inbound.Settings = strings.Replace(inbound.Settings, "0123456789abcdef", "1123456789abcdef", 1)
	mgr.Reconcile([]*model.Inbound{inbound})
	second := mgr.procs[3]
	if second == first || first.Running() {
		t.Fatal("credential update did not replace the process")
	}
	inbound.Port++
	mgr.Reconcile([]*model.Inbound{inbound})
	if mgr.procs[3] == second || second.Running() {
		t.Fatal("port update did not replace the process")
	}
	inbound.Enable = false
	mgr.Reconcile([]*model.Inbound{inbound})
	if len(mgr.procs) != 0 {
		t.Fatal("disabled inbound still has a process")
	}
	if _, err := os.Stat(configPath(3)); !os.IsNotExist(err) {
		t.Fatal("disabled config was not removed")
	}
}

func TestConcurrentTrafficPollsDoNotDoubleCountOrReturnNegativeDeltas(t *testing.T) {
	var mu sync.Mutex
	up, down := int64(100), int64(200)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, `{"users":{"test":{"bytes_in":%d,"bytes_out":%d}}}`, up, down)
	}))
	defer server.Close()
	mgr := newManager()
	mgr.ports[1] = server.Listener.Addr().(*net.TCPAddr).Port
	mgr.tokens[1] = "token"
	mgr.procs[1] = newProcess("")
	var wg sync.WaitGroup
	results := make(chan []*xray.ClientTraffic, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- mgr.CollectTraffic() }()
	}
	wg.Wait()
	close(results)
	var totalUp, totalDown int64
	for result := range results {
		for _, item := range result {
			totalUp += item.Up
			totalDown += item.Down
		}
	}
	if totalUp != 100 || totalDown != 200 {
		t.Fatalf("double-counted: %d/%d", totalUp, totalDown)
	}
	mu.Lock()
	up, down = 5, 210
	mu.Unlock()
	result := mgr.CollectTraffic()
	if len(result) != 1 || result[0].Up != 0 || result[0].Down != 10 {
		t.Fatalf("counter reset: %+v", result)
	}
	mgr.RetryTraffic(result)
	if retry := mgr.CollectTraffic(); len(retry) != 1 || retry[0].Down != 10 {
		t.Fatal("failed database interval was lost")
	}
}

func TestLateStatsResponseCannotResurrectRestartedInstance(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		fmt.Fprint(w, `{"users":{"old":{"bytes_in":100,"bytes_out":200}}}`)
	}))
	defer server.Close()
	mgr := newManager()
	mgr.ports[1] = server.Listener.Addr().(*net.TCPAddr).Port
	mgr.procs[1] = newProcess("old")
	result := make(chan []*xray.ClientTraffic, 1)
	go func() { result <- mgr.CollectTraffic() }()
	<-started
	mgr.mu.Lock()
	mgr.procs[1] = newProcess("new")
	mgr.last[1] = map[string]statsCounter{}
	mgr.mu.Unlock()
	close(release)
	if traffic := <-result; len(traffic) != 0 {
		t.Fatal("old stats attributed to new process")
	}
	if len(mgr.last[1]) != 0 {
		t.Fatal("new baseline overwritten")
	}
}

// Optional integration check against the packaged mtg-multi binary. No public
// proxy is exposed: both listeners are bound to loopback and stopped afterward.
func TestPackagedMTGRuntimeAcceptsGeneratedConfig(t *testing.T) {
	binary := os.Getenv("MTPROTO_TEST_BINARY")
	if binary == "" {
		t.Skip("set MTPROTO_TEST_BINARY for the native runtime check")
	}
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())
	if err := os.Symlink(binary, binaryPath()); err != nil {
		t.Fatal(err)
	}
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	mgr := newManager()
	t.Cleanup(mgr.StopAll)
	inbound := &model.Inbound{Id: 1, Protocol: Protocol, Enable: true, Listen: "127.0.0.1", Port: port, Settings: fmt.Sprintf(`{"clients":[{"email":"test","secret":%q,"enable":true}]}`, testSecret)}
	mgr.Reconcile([]*model.Inbound{inbound})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := scrapeStats(mgr.ports[1], mgr.tokens[1]); ok {
			data, err := os.ReadFile(filepath.Join(configDir(), "mtg-1.toml"))
			if err != nil {
				t.Fatal(err)
			}
			var parsed map[string]interface{}
			if err := toml.Unmarshal(data, &parsed); err != nil {
				t.Fatal(err)
			}
			if encoded, err := json.Marshal(parsed); err != nil || len(encoded) == 0 {
				t.Fatal("invalid generated config")
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("packaged mtg did not expose its authenticated stats endpoint")
}
