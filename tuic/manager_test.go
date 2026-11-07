package tuic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"x-ui/database/model"
	"x-ui/xray"

	"github.com/quic-go/quic-go"
)

const testUUID = "11111111-2222-3333-4444-555555555555"

func TestNativeConfigMapsUpstreamSettingsAndFiltersPanelFields(t *testing.T) {
	inbound := &model.Inbound{Protocol: Protocol, Listen: "::1", Port: 8443, Settings: `{"server":{"certificate":"cert.pem","private_key":"key.pem","authentication_timeout":3,"max_idle_time":15,"max_udp_relay_packet_size":1500,"sni":"proxy.example","udp_relay_mode":"quic"},"clients":[{"email":"client","uuid":"11111111-2222-3333-4444-555555555555","password":"secret","enable":true,"subId":"subscription"}]}`}
	encoded, err := NativeConfig(inbound, true)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got["server"] != "[::1]:8443" || got["auth_timeout"] != "3s" || got["max_idle_time"] != "15s" || got["max_external_packet_size"] != float64(1500) {
		t.Fatalf("bad native settings: %s", encoded)
	}
	for _, key := range []string{"clients", "sni", "udp_relay_mode", "authentication_timeout", "max_udp_relay_packet_size"} {
		if _, exists := got[key]; exists {
			t.Fatalf("panel field %s leaks to deny_unknown_fields runtime", key)
		}
	}
	if got["users"].(map[string]interface{})[testUUID] != "secret" {
		t.Fatal("panel UUID/password not converted to native users map")
	}
}

func TestNativeConfigCannotRestoreDisabledOrExpiredUsers(t *testing.T) {
	inbound := &model.Inbound{Protocol: Protocol, Enable: true, Port: 8443, Settings: `{"certificate":"cert.pem","private_key":"key.pem","users":{"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa":"stale"},"clients":[{"email":"disabled","id":"11111111-2222-3333-4444-555555555555","password":"secret","enable":false},{"email":"expired","id":"21111111-2222-3333-4444-555555555555","password":"secret","expiryTime":1},{"email":"depleted","id":"31111111-2222-3333-4444-555555555555","password":"secret"}]}`}
	inbound.ClientStats = []xray.ClientTraffic{{Email: "depleted", Enable: false}}
	if _, ok := parseInstance(inbound); ok {
		t.Fatal("disabled clients or stale users map are still served")
	}
}

func TestNativeConfigTopLevelOverridesNestedServer(t *testing.T) {
	inbound := &model.Inbound{Protocol: Protocol, Port: 8443, Settings: `{"server":{"certificate":"nested-cert.pem","private_key":"key.pem","alpn":["nested"],"congestion_control":"cubic"},"certificate":"flat-cert.pem","alpn":["flat"],"congestion_control":"bbr","clients":[{"email":"client","id":"` + testUUID + `","password":"secret","enable":true}]}`}
	encoded, err := NativeConfig(inbound, true)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Certificate string   `json:"certificate"`
		PrivateKey  string   `json:"private_key"`
		ALPN        []string `json:"alpn"`
		Congestion  string   `json:"congestion_control"`
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.Certificate != "flat-cert.pem" || got.PrivateKey != "key.pem" || len(got.ALPN) != 1 || got.ALPN[0] != "flat" || got.Congestion != "bbr" {
		t.Fatalf("flat overrides or nested fallback lost: %s", encoded)
	}
}

func TestNativeConfigCanonicalIDOverridesLegacyUUID(t *testing.T) {
	const rotatedUUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	inbound := &model.Inbound{Protocol: Protocol, Port: 8443, Settings: `{"certificate":"cert.pem","private_key":"key.pem","clients":[{"email":"client","id":"` + rotatedUUID + `","uuid":"` + testUUID + `","password":"secret","enable":true}]}`}
	encoded, err := NativeConfig(inbound, true)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Users map[string]string `json:"users"`
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.Users[rotatedUUID] != "secret" || len(got.Users) != 1 {
		t.Fatalf("rotated canonical id was not used: %s", encoded)
	}
	if _, exists := got.Users[testUUID]; exists {
		t.Fatal("legacy UUID is still authorized after rotation")
	}
}

func TestNativeConfigRejectsUnenforcedQuotasAndInvalidCredentials(t *testing.T) {
	base := `{"certificate":"cert.pem","private_key":"key.pem","clients":[{"email":"client","id":"11111111-2222-3333-4444-555555555555","password":"secret"}]}`
	tests := []struct {
		name     string
		settings string
		total    int64
	}{
		{"inbound quota", base, 1},
		{"client quota", strings.Replace(base, `"password":"secret"`, `"password":"secret","totalGB":1`, 1), 0},
		{"delayed start", strings.Replace(base, `"password":"secret"`, `"password":"secret","expiryTime":-86400000`, 1), 0},
		{"invalid uuid", strings.Replace(base, testUUID, "not-a-uuid", 1), 0},
		{"empty password", strings.Replace(base, `"password":"secret"`, `"password":""`, 1), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NativeConfig(&model.Inbound{Protocol: Protocol, Port: 8443, Settings: tt.settings, Total: tt.total}, false); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestNativeConfigAllowsAbsoluteExpiry(t *testing.T) {
	settings, err := json.Marshal(map[string]interface{}{
		"certificate": "cert.pem", "private_key": "key.pem",
		"clients": []map[string]interface{}{{"email": "client", "id": testUUID, "password": "secret", "enable": true, "expiryTime": time.Now().Add(time.Hour).UnixMilli()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	inbound := &model.Inbound{Protocol: Protocol, Port: 8443, Settings: string(settings)}
	encoded, err := NativeConfig(inbound, true)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Users map[string]string `json:"users"`
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.Users[testUUID] != "secret" {
		t.Fatal("client with a future absolute expiry was filtered")
	}
}

func testCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// This exercises the packaged server's actual serde parser and QUIC/TLS
// listener, not merely a comparison against a hand-written expected map.
func TestPackagedTUICRuntimeAcceptsPanelConfig(t *testing.T) {
	binary := os.Getenv("TUIC_TEST_BINARY")
	if binary == "" {
		t.Skip("set TUIC_TEST_BINARY for the native runtime check")
	}
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	if err := os.Symlink(binary, binaryPath()); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := testCertificate(t, dir)
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	listener.Close()
	settings, _ := json.Marshal(map[string]interface{}{"server": map[string]interface{}{"certificate": certPath, "private_key": keyPath, "authentication_timeout": 3, "max_idle_time": 15, "max_udp_relay_packet_size": 1500, "sni": "localhost"}, "clients": []map[string]interface{}{{"email": "test", "uuid": testUUID, "password": "secret", "enable": true}}})
	inbound := &model.Inbound{Id: 1, Protocol: Protocol, Enable: true, Listen: "127.0.0.1", Port: port, Settings: string(settings)}
	if err := ValidateSettings(inbound); err != nil {
		t.Fatal(err)
	}
	mgr := &Manager{procs: map[int]*Process{}, state: map[int]string{}}
	t.Cleanup(mgr.StopAll)
	mgr.Reconcile([]*model.Inbound{inbound})
	var lastErr error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := quic.DialAddr(ctx, listener.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, ServerName: "localhost"}, &quic.Config{EnableDatagrams: true})
		cancel()
		if err == nil {
			conn.CloseWithError(0, "test complete")
			return
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("packaged TUIC failed its QUIC/TLS handshake: %v", lastErr)
}
