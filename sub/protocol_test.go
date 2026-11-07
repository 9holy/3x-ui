package sub

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"x-ui/database/model"
)

func decodeLink(t *testing.T, link string) *url.URL {
	t.Helper()
	if link == "" {
		t.Fatal("empty share link")
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestHysteriaLinksPreserveCredentialsTLSAndObfuscation(t *testing.T) {
	s := NewSubService(false, "-ieo")
	s.address = "2001:db8::1"
	auth := "user:p@ss/?#% +"
	settings, _ := json.Marshal(map[string]interface{}{"version": 2, "clients": []interface{}{map[string]interface{}{"email": "a", "auth": auth, "enable": true}}})
	inbound := &model.Inbound{Protocol: model.Hysteria, Port: 443, Settings: string(settings), StreamSettings: `{"security":"tls","tlsSettings":{"serverName":"cert.example","alpn":["h3"],"settings":{"echConfigList":"ech-value"}},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"obfs-password"}},{"type":"udphop","settings":{"remotePorts":"2000-3000"}}]}}`}
	u := decodeLink(t, s.getLink(inbound, "a"))
	if u.Host != "[2001:db8::1]:443" || u.User.Username() != auth {
		t.Fatalf("IPv6 or auth changed: %s", u)
	}
	for key, want := range map[string]string{"sni": "cert.example", "alpn": "h3", "ech": "ech-value", "obfs": "salamander", "obfs-password": "obfs-password", "mport": "2000-3000"} {
		if u.Query().Get(key) != want {
			t.Errorf("%s = %q, want %q", key, u.Query().Get(key), want)
		}
	}
	if u.Query().Has("fm") {
		t.Fatal("nonstandard finalmask JSON leaked into a standard Hysteria URI")
	}
}

func TestTUICLinksUseConfiguredParameters(t *testing.T) {
	s := NewSubService(false, "-ieo")
	s.address = "proxy.example"
	ib := &model.Inbound{Protocol: model.TUIC, Port: 8443, Settings: `{"clients":[{"email":"a","uuid":"1234","password":"p:@/?#%","enable":true}],"alpn":["h3","custom"],"sni":"certificate.example","congestion_control":"cubic","udp_relay_mode":"quic"}`, StreamSettings: `{}`}
	u := decodeLink(t, s.getLink(ib, "a"))
	pw, _ := u.User.Password()
	if u.User.Username() != "1234" || pw != "p:@/?#%" || u.Query().Get("sni") != "certificate.example" || u.Query().Get("alpn") != "h3,custom" || u.Query().Get("congestion_control") != "cubic" || u.Query().Get("udp_relay_mode") != "quic" {
		t.Fatalf("TUIC fields lost: %s", u)
	}
}

func TestTUICLinksReadNestedServerWithCanonicalOverrides(t *testing.T) {
	s := NewSubService(false, "-ieo")
	s.address = "example.com"
	ib := &model.Inbound{Protocol: model.TUIC, Port: 443, Settings: `{"clients":[{"id":"new-id","uuid":"old-id","email":"a","password":"pw","enable":true}],"server":{"sni":"cert.example","alpn":["custom"],"congestion_control":"cubic"},"congestion_control":"bbr"}`, StreamSettings: `{}`}
	u := decodeLink(t, s.getLink(ib, "a"))
	if u.User.Username() != "new-id" || u.Query().Get("sni") != "cert.example" || u.Query().Get("alpn") != "custom" || u.Query().Get("congestion_control") != "bbr" {
		t.Fatalf("TUIC runtime/share mismatch: %s", u)
	}
}

func TestVLESSXHTTPEncryptionAndRealityLink(t *testing.T) {
	s := NewSubService(false, "-ieo")
	s.address = "2001:db8::2"
	ib := &model.Inbound{Protocol: model.VLESS, Port: 443, Settings: `{"encryption":"mlkem768x25519plus.native.0rtt.test","decryption":"private-server-key","clients":[{"id":"test:@id","email":"a","flow":"xtls-rprx-vision","enable":true}]}`, StreamSettings: `{"network":"xhttp","security":"reality","xhttpSettings":{"path":"/x","host":"cdn.example","mode":"packet-up","xPaddingBytes":"200-500","sessionKey":"custom","h2Params":{"MaxConcurrentStreams":512}},"realitySettings":{"privateKey":"SERVER_SECRET","serverNames":["cover.example"],"shortIds":["ab"],"settings":{"publicKey":"public","mldsa65Verify":"verify","fingerprint":"chrome"}}}`}
	u := decodeLink(t, s.getLink(ib, "a"))
	if u.User.Username() != "test:@id" || u.Hostname() != "2001:db8::2" || u.Query().Get("pqv") != "verify" || u.Query().Get("flow") != "xtls-rprx-vision" || u.Query().Get("encryption") != "mlkem768x25519plus.native.0rtt.test" {
		t.Fatalf("VLESS attributes lost: %s", u)
	}
	extra := jsonObject(u.Query().Get("extra"))
	if extra["sessionIDKey"] != "custom" || extra["xPaddingBytes"] != "200-500" || extra["h2Params"] != nil || strings.Contains(u.String(), "SERVER_SECRET") {
		t.Fatalf("wrong XHTTP or REALITY client data: %s", u)
	}
	js := NewSubJsonService("", "", "", "", s)
	configs := js.getConfig(ib, model.Client{ID: "test:@id", Email: "a", Flow: "xtls-rprx-vision"}, s.address)
	if len(configs) != 1 || strings.Contains(string(configs[0]), "SERVER_SECRET") {
		t.Fatalf("invalid client JSON: %s", configs)
	}
	config := jsonObject(string(configs[0]))
	proxy := object(config["outbounds"].([]interface{})[0])
	vnext := object(object(proxy["settings"])["vnext"].([]interface{})[0])
	user := object(vnext["users"].([]interface{})[0])
	if user["encryption"] != "mlkem768x25519plus.native.0rtt.test" {
		t.Fatalf("VLESS encryption reset: %v", user)
	}
}

func TestKCPModernMasksAndLegacySettingsHaveSameShareParameters(t *testing.T) {
	s := NewSubService(false, "-ieo")
	s.address = "proxy.example"
	for _, stream := range []string{
		`{"network":"kcp","kcpSettings":{"seed":"abc","header":{"type":"wechat-video"},"mtu":1350,"tti":20}}`,
		`{"network":"kcp","kcpSettings":{"mtu":1350,"tti":20},"finalmask":{"udp":[{"type":"mkcp-legacy","settings":{"header":"","value":"abc"}},{"type":"mkcp-legacy","settings":{"header":"wechat"}}]}}`,
	} {
		ib := &model.Inbound{Protocol: model.VLESS, Port: 443, Settings: `{"clients":[{"id":"uuid","email":"a","enable":true}]}`, StreamSettings: stream}
		u := decodeLink(t, s.getLink(ib, "a"))
		if u.Query().Get("seed") != "abc" || u.Query().Get("headerType") != "wechat-video" || u.Query().Get("mtu") != "1350" {
			t.Fatalf("KCP fields lost: %s", u)
		}
	}
}

func TestJSONUnsupportedSidecarsDoNotBecomeDirectConnections(t *testing.T) {
	s := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
	for _, protocol := range []model.Protocol{model.TUIC, model.MTProto, model.AmneziaWG, model.Tun} {
		if configs := s.getConfig(&model.Inbound{Protocol: protocol, StreamSettings: `{}`}, model.Client{Email: "a"}, "example.com"); len(configs) != 0 {
			t.Errorf("%s generated a fake Xray subscription: %s", protocol, configs)
		}
	}
}

func TestHysteriaAndMasqueJSONAuthentication(t *testing.T) {
	s := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
	for _, protocol := range []model.Protocol{model.Hysteria, model.Masque} {
		ib := &model.Inbound{Protocol: protocol, Port: 443, StreamSettings: `{"security":"tls","tlsSettings":{"serverName":"cert.example","settings":{"pinnedPeerCertSha256":["pin-one","pin-two"]},"certificates":[{"keyFile":"SERVER_KEY"}]},"masqueSettings":{"path":"/masque"}}`}
		configs := s.getConfig(ib, model.Client{Email: "a", Auth: "hy-auth", Password: "masque-pass"}, "example.com")
		if len(configs) != 1 {
			t.Fatalf("no %s config", protocol)
		}
		config := jsonObject(string(configs[0]))
		proxy := object(config["outbounds"].([]interface{})[0])
		stream := object(proxy["streamSettings"])
		if proxy["protocol"] != string(protocol) || stream["network"] != string(protocol) || strings.Contains(string(configs[0]), "SERVER_KEY") {
			t.Fatalf("invalid QUIC client config: %s", configs[0])
		}
		if object(stream["tlsSettings"])["pinnedPeerCertSha256"] != "pin-one,pin-two" {
			t.Fatal("TLS pin array not converted to core string")
		}
		if protocol == model.Hysteria && object(stream["hysteriaSettings"])["auth"] != "hy-auth" || protocol == model.Masque && object(stream["masqueSettings"])["pass"] != "masque-pass" {
			t.Fatalf("missing auth: %s", configs[0])
		}
	}
}

func TestExternalProxyJSONDoesNotMutateNextEndpoint(t *testing.T) {
	s := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
	ib := &model.Inbound{Protocol: model.VLESS, Port: 443, Settings: `{"encryption":"none"}`, StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"cert.example"},"externalProxy":[{"dest":"one.example","port":80,"forceTls":"none"},{"dest":"two.example","port":443,"forceTls":"same"}]}`}
	configs := s.getConfig(ib, model.Client{ID: "uuid", Email: "a"}, "example.com")
	if len(configs) != 2 {
		t.Fatal("expected two endpoints")
	}
	for i, want := range []string{"none", "tls"} {
		cfg := jsonObject(string(configs[i]))
		proxy := object(cfg["outbounds"].([]interface{})[0])
		if object(proxy["streamSettings"])["security"] != want {
			t.Fatalf("endpoint %d security was mutated: %s", i, configs[i])
		}
	}
	if ib.Listen != "" || ib.Port != 443 {
		t.Fatal("subscription rendering mutated the stored inbound")
	}
}

func TestLegacyVMessAndShadowsocksLinks(t *testing.T) {
	s := NewSubService(false, "-ieo")
	s.address = "example.com"
	vm := &model.Inbound{Protocol: model.VMESS, Port: 443, Settings: `{"clients":[{"id":"uuid","security":"auto","email":"a","enable":true}]}`, StreamSettings: `{"network":"ws","security":"tls","wsSettings":{"path":"/socket","host":"cdn.example"},"tlsSettings":{"serverName":"cert.example"}}`}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s.getLink(vm, "a"), "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	obj := jsonObject(string(raw))
	if obj["net"] != "ws" || obj["path"] != "/socket" || obj["scy"] != "auto" || obj["id"] != "uuid" {
		t.Fatalf("legacy VMess changed: %s", raw)
	}
	ss := &model.Inbound{Protocol: model.Shadowsocks, Port: 443, Settings: `{"method":"2022-blake3-aes-128-gcm","password":"server","clients":[{"email":"a","password":"client","enable":true}]}`, StreamSettings: `{"network":"tcp","security":"none"}`}
	u := decodeLink(t, s.getLink(ss, "a"))
	cred, err := base64.RawURLEncoding.DecodeString(u.User.Username())
	if err != nil || string(cred) != "2022-blake3-aes-128-gcm:server:client" {
		t.Fatalf("Shadowsocks 2022 PSKs lost: %s %v", cred, err)
	}
}

func TestJSONDoesNotLeakInactiveSecurityPrivateKeys(t *testing.T) {
	s := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
	for _, security := range []string{"none", "tls", "reality"} {
		stream := map[string]interface{}{
			"security":        security,
			"tlsSettings":     map[string]interface{}{"serverName": "public.example", "certificates": []interface{}{map[string]interface{}{"key": "TLS_PRIVATE_SENTINEL"}}},
			"realitySettings": map[string]interface{}{"privateKey": "REALITY_PRIVATE_SENTINEL", "settings": map[string]interface{}{"publicKey": "public"}},
			"xtlsSettings":    map[string]interface{}{"key": "XTLS_PRIVATE_SENTINEL"},
		}
		encoded, _ := json.Marshal(stream)
		client := s.streamData(string(encoded))
		got, _ := json.Marshal(client)
		if strings.Contains(string(got), "PRIVATE_SENTINEL") {
			t.Fatalf("%s security leaked a server key: %s", security, got)
		}
	}
}

func TestJSONDropsVisionForXDRIVEAndUnencryptedExternalEndpoint(t *testing.T) {
	s := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
	for _, stream := range []string{
		`{"network":"xdrive","security":"none","xdriveSettings":{"service":"s3"}}`,
		`{"network":"tcp","security":"tls","tlsSettings":{},"externalProxy":[{"dest":"example.com","port":80,"forceTls":"none"}]}`,
	} {
		ib := &model.Inbound{Protocol: model.VLESS, Port: 443, Settings: `{"encryption":"none"}`, StreamSettings: stream}
		configs := s.getConfig(ib, model.Client{ID: "uuid", Email: "a", Flow: "xtls-rprx-vision"}, "example.com")
		if len(configs) != 1 || strings.Contains(string(configs[0]), `"flow"`) {
			t.Fatalf("incompatible Vision flow survived: %s", configs)
		}
	}
}

func TestTLSVerificationAndRealityAliases(t *testing.T) {
	s := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
	tls := s.tlsData(jsonObject(`{"settings":{"verifyPeerCertByName":["a.example","b.example"],"pinnedPeerCertSha256":["pin1","pin2"]}}`))
	if tls["verifyPeerCertByName"] != "a.example,b.example" || tls["pinnedPeerCertSha256"] != "pin1,pin2" {
		t.Fatalf("invalid verification format: %v", tls)
	}
	reality := s.realityData(jsonObject(`{"settings":{"password":"public-key","spiderX":"/custom","mldsa65Verify":"verify"}}`))
	if reality["publicKey"] != "public-key" || reality["spiderX"] != "/custom" || reality["mldsa65Verify"] != "verify" {
		t.Fatalf("REALITY aliases lost: %v", reality)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if got := hysteriaPinHex(enc.EncodeToString(make([]byte, 32))); got != strings.Repeat("0", 64) {
			t.Fatalf("invalid HY2 cert pin: %q", got)
		}
	}
}

func TestJSONKeepsVisionForImplicitTCP(t *testing.T) {
	s := NewSubJsonService("", "", "", "", NewSubService(false, "-ieo"))
	ib := &model.Inbound{Protocol: model.VLESS, Port: 443, Settings: `{"encryption":"none"}`, StreamSettings: `{"security":"tls","tlsSettings":{}}`}
	configs := s.getConfig(ib, model.Client{ID: "uuid", Email: "a", Flow: "xtls-rprx-vision"}, "example.com")
	if len(configs) != 1 || !strings.Contains(string(configs[0]), `"flow":"xtls-rprx-vision"`) {
		t.Fatalf("implicit TCP lost Vision: %s", configs)
	}
}
