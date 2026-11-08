package model

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestTunnelModernSettingsKeepPrecedence(t *testing.T) {
	raw := coreProtocolSettings(Tunnel, `{"address":"old","rewriteAddress":"new","port":80,"network":"tcp,udp"}`)
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got["rewriteAddress"] != "new" || got["rewritePort"] != float64(80) || got["allowedNetwork"] != "tcp,udp" || got["address"] != nil {
		t.Fatal(raw)
	}
}

func TestWireGuardDerivesStoredClientPublicKeyWithoutLeakingPrivateKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	priv, _ := ecdh.X25519().NewPrivateKey(key)
	want := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	for _, raw := range []string{hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key)} {
		got := coreProtocolSettings(WireGuard, `{"peers":[{"privateKey":"`+raw+`","allowedIPs":["10.0.0.2/32"]}]}`)
		if strings.Contains(got, "privateKey") || !strings.Contains(got, want) {
			t.Fatal(got)
		}
	}
}
