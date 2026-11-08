package xray

import (
	"encoding/json"
	"testing"
)

func TestNormalizeLegacyKCPIsIdempotent(t *testing.T) {
	raw := `{"network":"kcp","kcpSettings":{"seed":"seed","header":{"type":"wechat-video"},"readBufferSize":2},"finalmask":{"udp":[{"type":"noise","settings":{"packet":"test"}}]}}`
	normalized := NormalizeStreamSettings(raw)
	var stream map[string]interface{}
	if err := json.Unmarshal([]byte(normalized), &stream); err != nil {
		t.Fatal(err)
	}
	kcp := stream["kcpSettings"].(map[string]interface{})
	if kcp["header"] != nil || kcp["seed"] != nil || kcp["readBufferSize"] != nil {
		t.Fatal("obsolete KCP fields retained")
	}
	masks := stream["finalmask"].(map[string]interface{})["udp"].([]interface{})
	if len(masks) != 3 {
		t.Fatalf("wanted existing mask + seed + header: %s", normalized)
	}
	if NormalizeStreamSettings(normalized) != normalized {
		t.Fatal("second normalization changed masks")
	}
}

func TestNormalizeUDPHopKeepsLastSocketMask(t *testing.T) {
	raw := `{"network":"hysteria","finalmask":{"quicParams":{"udpHop":{"ports":"1000-2000","interval":"30"}},"udp":[{"type":"udphop","settings":{"remotePorts":"3000-4000"}},{"type":"salamander","settings":{"password":"secret"}}]}}`
	var stream map[string]interface{}
	_ = json.Unmarshal([]byte(NormalizeStreamSettings(raw)), &stream)
	fm := stream["finalmask"].(map[string]interface{})
	if fm["quicParams"] != nil {
		t.Fatal("obsolete udpHop retained")
	}
	masks := fm["udp"].([]interface{})
	last := masks[len(masks)-1].(map[string]interface{})
	if last["type"] != "udphop" || last["settings"].(map[string]interface{})["remotePorts"] != "3000-4000" {
		t.Fatal("explicit hop lost or not last")
	}
}

func TestLegacyKCPWithoutSeedPreservesOriginalAuthenticator(t *testing.T) {
	for _, header := range []string{"none", "srtp"} {
		raw := `{"network":"kcp","kcpSettings":{"header":{"type":"` + header + `"}}}`
		var stream map[string]interface{}
		_ = json.Unmarshal([]byte(NormalizeStreamSettings(raw)), &stream)
		masks := stream["finalmask"].(map[string]interface{})["udp"].([]interface{})
		first := masks[0].(map[string]interface{})["settings"].(map[string]interface{})
		if first["header"] != "" || first["value"] != "" {
			t.Fatalf("original KCP authenticator lost: %s", NormalizeStreamSettings(raw))
		}
	}
	modern := `{"network":"kcp","kcpSettings":{"mtu":1350}}`
	var stream map[string]interface{}
	_ = json.Unmarshal([]byte(NormalizeStreamSettings(modern)), &stream)
	if stream["finalmask"] != nil {
		t.Fatal("modern KCP unexpectedly changed wire authentication")
	}
	if CheckLegacyStreamSettings(`{"network":"kcp","kcpSettings":{"seed":""}}`) == nil {
		t.Fatal("ambiguous empty seed was silently migrated")
	}
}

func TestUnsupportedUserUpdateRequiresRestart(t *testing.T) {
	for _, protocol := range []string{"hysteria", "masque", "tuic", "amneziawg"} {
		if err := (&XrayAPI{}).AddUser(protocol, "in", nil); err == nil {
			t.Errorf("%s silently accepted an unimplemented hot update", protocol)
		}
	}
}
