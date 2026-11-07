package model

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoreCredentialsAndDisabledClients(t *testing.T) {
	for _, tc := range []struct {
		protocol    Protocol
		settings    string
		field, want string
	}{
		{Hysteria, `{"clients":[{"email":"a","auth":"hy-secret","enable":true,"subId":"private-sub"},{"email":"off","auth":"off-secret","enable":false}]}`, "auth", "hy-secret"},
		{Masque, `{"clients":[{"email":"a","password":"masque-secret","enable":true,"subId":"private-sub"},{"email":"off","password":"off-secret","enable":false}]}`, "pass", "masque-secret"},
	} {
		in := &Inbound{Protocol: tc.protocol, Settings: tc.settings, StreamSettings: `{}`}
		cfg := in.GenXrayInboundConfig()
		var settings map[string]interface{}
		if err := json.Unmarshal(cfg.Settings, &settings); err != nil {
			t.Fatal(err)
		}
		clients := settings["clients"].([]interface{})
		if len(clients) != 1 || clients[0].(map[string]interface{})[tc.field] != tc.want {
			t.Fatalf("credentials lost: %s", cfg.Settings)
		}
		if strings.Contains(string(cfg.Settings), "private-sub") || strings.Contains(string(cfg.Settings), "off-secret") {
			t.Fatalf("panel metadata/disabled client leaked: %s", cfg.Settings)
		}
		if in.Settings != tc.settings {
			t.Fatal("database input mutated")
		}
		if tc.protocol == Hysteria && settings["version"] != float64(2) {
			t.Fatal("HY2 version missing")
		}
	}
}

func TestVLESSKeepsServerDecryptionOnly(t *testing.T) {
	in := &Inbound{Protocol: VLESS, Listen: `127.0.0.1"`, Settings: `{"decryption":"server","encryption":"client","clients":[{"id":"id","flow":"xtls-rprx-vision-udp443","enable":true}]}`}
	cfg := in.GenXrayInboundConfig()
	var settings map[string]interface{}
	_ = json.Unmarshal(cfg.Settings, &settings)
	if settings["encryption"] != nil || settings["decryption"] != "server" {
		t.Fatalf("wrong VLESS server settings: %s", cfg.Settings)
	}
	if !json.Valid(cfg.Listen) {
		t.Fatalf("listen was not JSON escaped: %s", cfg.Listen)
	}
}

func TestMasqueEditedCanonicalPasswordReplacesLegacyPass(t *testing.T) {
	ib := &Inbound{Protocol: Masque, Settings: `{"clients":[{"email":"a","pass":"old-password","password":"new-password","enable":true}]}`, StreamSettings: `{}`}
	cfg := ib.GenXrayInboundConfig()
	var settings map[string]interface{}
	_ = json.Unmarshal(cfg.Settings, &settings)
	client := settings["clients"].([]interface{})[0].(map[string]interface{})
	if client["pass"] != "new-password" || client["password"] != nil || strings.Contains(string(cfg.Settings), "old-password") {
		t.Fatalf("edited password did not replace alias: %s", cfg.Settings)
	}
}

// Run with XUI_TEST_XRAY pointing at the packaged core. These are real core
// configuration checks, not comparisons with another copy of the serializer.
func TestNativeCoreProtocolConfigurations(t *testing.T) {
	binary := os.Getenv("XUI_TEST_XRAY")
	if binary == "" {
		t.Skip("set XUI_TEST_XRAY to validate against the packaged Xray core")
	}
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	tls := map[string]interface{}{"certificates": []interface{}{map[string]interface{}{"certificateFile": certFile, "keyFile": keyFile}}}
	tlsStream := func(network string) string {
		value, _ := json.Marshal(map[string]interface{}{"network": network, "security": "tls", "tlsSettings": tls, network + "Settings": map[string]interface{}{"version": 2}})
		return string(value)
	}
	uuid := "11111111-1111-4111-8111-111111111111"
	cases := []Inbound{
		{Tag: "vmess", Protocol: VMESS, Settings: `{"clients":[{"id":"` + uuid + `","email":"a","security":"auto"}]}`, StreamSettings: `{"network":"tcp"}`},
		{Tag: "vless", Protocol: VLESS, Settings: `{"decryption":"none","encryption":"none","clients":[{"id":"` + uuid + `","email":"a"}]}`, StreamSettings: `{"network":"tcp"}`},
		{Tag: "trojan", Protocol: Trojan, Settings: `{"clients":[{"password":"test-password","email":"a"}]}`, StreamSettings: tlsStream("tcp")},
		{Tag: "shadowsocks", Protocol: Shadowsocks, Settings: `{"method":"aes-128-gcm","password":"test-password","network":"tcp,udp"}`},
		{Tag: "socks", Protocol: Socks, Settings: `{"auth":"noauth","udp":true}`},
		{Tag: "mixed", Protocol: Mixed, Settings: `{"auth":"noauth","udp":true}`},
		{Tag: "http", Protocol: HTTP, Settings: `{}`},
		{Tag: "dokodemo", Protocol: DOKODEMO, Settings: `{"address":"127.0.0.1","port":80,"network":"tcp"}`},
		{Tag: "tunnel", Protocol: Tunnel, Settings: `{"address":"127.0.0.1","port":80,"network":"tcp"}`},
		{Tag: "hysteria", Protocol: Hysteria, Settings: `{"version":1,"clients":[{"email":"a","auth":"hy-secret","enable":true}]}`, StreamSettings: tlsStream("hysteria")},
		{Tag: "masque", Protocol: Masque, Settings: `{"clients":[{"email":"a","password":"masque-secret","enable":true}]}`, StreamSettings: tlsStream("masque")},
		{Tag: "legacy-kcp", Protocol: VLESS, Settings: `{"decryption":"none","clients":[{"id":"` + uuid + `"}]}`, StreamSettings: `{"network":"kcp","kcpSettings":{"seed":"test","header":{"type":"wechat-video"},"congestion":false,"readBufferSize":2,"writeBufferSize":2}}`},
		{Tag: "legacy-splithttp", Protocol: VLESS, Settings: `{"decryption":"none","clients":[{"id":"` + uuid + `"}]}`, StreamSettings: `{"network":"splithttp","splithttpSettings":{"path":"/test","mode":"auto","xPaddingBytes":"100-200"}}`},
	}
	for _, in := range cases {
		t.Run(in.Tag, func(t *testing.T) {
			in.Listen = "127.0.0.1"
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			in.Port = listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			if in.Protocol == Hysteria {
				var stream map[string]interface{}
				_ = json.Unmarshal([]byte(in.StreamSettings), &stream)
				stream["finalmask"] = map[string]interface{}{"quicParams": map[string]interface{}{"udpHop": map[string]interface{}{"ports": "20000-30000", "interval": 30}}}
				encoded, _ := json.Marshal(stream)
				in.StreamSettings = string(encoded)
			}
			config, err := json.Marshal(map[string]interface{}{"inbounds": []interface{}{in.GenXrayInboundConfig()}, "outbounds": []interface{}{map[string]interface{}{"protocol": "freedom"}}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, in.Tag+".json")
			if err = os.WriteFile(path, config, 0600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(binary, "run", "-test", "-c", path).CombinedOutput()
			if err != nil {
				t.Fatalf("core rejected %s: %v\n%s", in.Tag, err, output)
			}
			// Configuration parsing alone does not exercise the transport's
			// listener wrappers (notably the client-only UDP hopping mask).
			ctx, cancel := context.WithCancel(context.Background())
			cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
			var log bytes.Buffer
			cmd.Stdout, cmd.Stderr = &log, &log
			if err := cmd.Start(); err != nil {
				cancel()
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				cancel()
				t.Fatalf("core failed to start %s: %v\n%s", in.Tag, err, log.String())
			case <-time.After(100 * time.Millisecond):
				cancel()
				<-done
			}
		})
	}
}
