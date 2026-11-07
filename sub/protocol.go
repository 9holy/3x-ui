package sub

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"x-ui/database/model"
	"x-ui/util/random"
	"x-ui/xray"
)

func object(value interface{}) map[string]interface{} {
	obj, _ := value.(map[string]interface{})
	if obj == nil {
		return map[string]interface{}{}
	}
	return obj
}

func jsonObject(raw string) map[string]interface{} {
	var obj map[string]interface{}
	_ = json.Unmarshal([]byte(raw), &obj)
	return object(obj)
}

func stringField(obj map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := obj[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func stringList(value interface{}) string {
	if str, ok := value.(string); ok {
		return str
	}
	var values []string
	if items, ok := value.([]interface{}); ok {
		for _, item := range items {
			if str, ok := item.(string); ok && str != "" {
				values = append(values, str)
			}
		}
	}
	return strings.Join(values, ",")
}

func hysteriaPinHex(pin string) string {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := encoding.DecodeString(pin); err == nil && len(raw) == 32 {
			return hex.EncodeToString(raw)
		}
	}
	return pin
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
}

func vlessClientEncryption(settings map[string]interface{}) string {
	if value := strings.TrimSpace(stringField(settings, "encryption")); value != "" {
		return value
	}
	return "none"
}

func supportsVLESSFlow(stream, settings map[string]interface{}) bool {
	network := stringField(stream, "network")
	if network == "xdrive" {
		return false
	}
	if vlessClientEncryption(settings) != "none" {
		return true
	}
	return (network == "" || network == "tcp" || network == "raw") && (stream["security"] == "tls" || stream["security"] == "reality")
}

func clientXHTTPSettings(settings map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(settings))
	for key, value := range settings {
		switch key {
		case "acceptProxyProtocol", "noSSEHeader", "scMaxBufferedPosts", "scStreamUpServerSecs", "serverMaxHeaderBytes", "h2Params":
			continue
		}
		if key == "scMaxEachPostBytes" && fmt.Sprint(value) == "1000000" || key == "scMinPostsIntervalMs" && fmt.Sprint(value) == "30" {
			continue
		}
		result[key] = value
	}
	return result
}

func streamShareParams(stream map[string]interface{}) map[string]string {
	params := map[string]string{"type": "tcp", "security": "none"}
	network := stringField(stream, "network")
	if network != "" {
		params["type"] = network
	}
	switch network {
	case "tcp", "raw", "":
		header := object(object(stream["tcpSettings"])["header"])
		if header["type"] == "http" {
			params["headerType"] = "http"
			request := object(header["request"])
			params["path"] = strings.Split(stringList(request["path"]), ",")[0]
			params["host"] = searchHost(request["headers"])
		}
	case "kcp":
		kcp := object(stream["kcpSettings"])
		for _, key := range []string{"mtu", "tti"} {
			if value, ok := kcp[key]; ok {
				params[key] = fmt.Sprint(value)
			}
		}
		masks, _ := object(stream["finalmask"])["udp"].([]interface{})
		for _, item := range masks {
			mask := object(item)
			if mask["type"] != "mkcp-legacy" {
				continue
			}
			settings := object(mask["settings"])
			if header := stringField(settings, "header"); header != "" {
				if header == "wechat" {
					header = "wechat-video"
				}
				params["headerType"] = header
			} else {
				params["seed"] = stringField(settings, "value")
			}
		}
	case "ws", "http", "httpupgrade", "xhttp":
		settings := object(stream[network+"Settings"])
		params["path"] = stringField(settings, "path")
		params["host"] = stringList(settings["host"])
		if params["host"] == "" {
			params["host"] = searchHost(settings["headers"])
		}
		if network == "xhttp" {
			params["mode"] = stringField(settings, "mode")
			params["x_padding_bytes"] = stringField(settings, "xPaddingBytes")
			extra := clientXHTTPSettings(settings)
			delete(extra, "path")
			delete(extra, "host")
			if len(extra) > 0 {
				encoded, _ := json.Marshal(extra)
				params["extra"] = string(encoded)
			}
		}
	case "grpc":
		settings := object(stream["grpcSettings"])
		params["serviceName"] = stringField(settings, "serviceName")
		params["authority"] = stringField(settings, "authority")
		if settings["multiMode"] == true {
			params["mode"] = "multi"
		}
	}
	security := stringField(stream, "security")
	if security == "tls" {
		params["security"] = "tls"
		applyTLSShareParams(params, object(stream["tlsSettings"]))
	} else if security == "reality" {
		params["security"] = "reality"
		reality := object(stream["realitySettings"])
		client := object(reality["settings"])
		params["pbk"] = stringField(client, "publicKey", "password")
		params["pqv"] = stringField(client, "mldsa65Verify")
		params["fp"] = stringField(client, "fingerprint")
		params["spx"] = stringField(client, "spiderX")
		if params["spx"] == "" {
			params["spx"] = "/" + random.Seq(15)
		}
		for source, dest := range map[string]string{"serverNames": "sni", "shortIds": "sid"} {
			if values, ok := reality[source].([]interface{}); ok && len(values) > 0 {
				params[dest], _ = values[random.Num(len(values))].(string)
			}
		}
	}
	if masks := object(stream["finalmask"]); len(masks) > 0 {
		encoded, _ := json.Marshal(clientFinalMask(masks))
		params["fm"] = string(encoded)
	}
	return params
}

func applyTLSShareParams(params map[string]string, tls map[string]interface{}) {
	params["sni"] = stringField(tls, "serverName")
	params["alpn"] = stringList(tls["alpn"])
	client := object(tls["settings"])
	if len(client) == 0 {
		client = tls
	}
	params["fp"] = stringField(client, "fingerprint")
	params["ech"] = stringField(client, "echConfigList")
	params["vcn"] = stringList(client["verifyPeerCertByName"])
	params["pcs"] = stringList(client["pinnedPeerCertSha256"])
}

func clientFinalMask(masks map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(masks))
	for key, value := range masks {
		if key == "tcp" || key == "udp" {
			items, _ := value.([]interface{})
			kept := make([]interface{}, 0, len(items))
			for _, item := range items {
				if object(item)["type"] != "filter" {
					kept = append(kept, item)
				}
			}
			if len(kept) > 0 {
				result[key] = kept
			}
		} else {
			result[key] = value
		}
	}
	return result
}

func (s *SubService) protocolShareLinks(inbound *model.Inbound, email string) string {
	if xray.CheckLegacyStreamSettings(inbound.StreamSettings) != nil {
		return ""
	}
	settings := jsonObject(inbound.Settings)
	stream := jsonObject(xray.NormalizeStreamSettings(inbound.StreamSettings))
	if stream["network"] == "xdrive" {
		// Storage credentials have no interoperable URI encoding. JSON export
		// carries the complete transport instead of advertising a broken link.
		return ""
	}
	var client map[string]interface{}
	clients, _ := settings["clients"].([]interface{})
	for _, item := range clients {
		c := object(item)
		if c["email"] == email {
			client = c
			break
		}
	}
	if client == nil || client["enable"] == false {
		return ""
	}
	params := streamShareParams(stream)
	scheme := string(inbound.Protocol)
	var user *url.Userinfo
	switch inbound.Protocol {
	case model.VMESS:
		if stringField(client, "id") == "" {
			return ""
		}
	case model.VLESS:
		user = url.User(stringField(client, "id"))
		params["encryption"] = vlessClientEncryption(settings)
		if supportsVLESSFlow(stream, settings) {
			params["flow"] = stringField(client, "flow")
		}
	case model.Trojan:
		user = url.User(stringField(client, "password"))
	case model.Shadowsocks:
		scheme = "ss"
		method, password := stringField(settings, "method"), stringField(client, "password")
		if strings.HasPrefix(method, "2022-") {
			password = stringField(settings, "password") + ":" + password
		}
		user = url.User(base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password)))
	case model.Hysteria:
		scheme = "hysteria2"
		user = url.User(stringField(client, "auth", "password", "secret"))
		params = map[string]string{"security": "tls"}
		applyTLSShareParams(params, object(stream["tlsSettings"]))
		if pins := params["pcs"]; pins != "" {
			values := strings.Split(pins, ",")
			for i, pin := range values {
				values[i] = hysteriaPinHex(pin)
			}
			params["pinSHA256"] = strings.Join(values, ",")
			delete(params, "pcs")
		}
		masks, _ := object(stream["finalmask"])["udp"].([]interface{})
		for _, item := range masks {
			mask := object(item)
			data := object(mask["settings"])
			switch mask["type"] {
			case "salamander":
				params["obfs"], params["obfs-password"] = "salamander", stringField(data, "password")
				if size := strings.Split(stringField(data, "packetSize"), "-"); len(size) == 2 {
					params["obfs"], params["minPacketSize"], params["maxPacketSize"] = "gecko", size[0], size[1]
				}
			case "udphop":
				params["mport"] = stringField(data, "remotePorts")
			}
		}
	case model.TUIC:
		// Upstream imports may keep runtime options under server. Match the
		// runtime adapter: explicit top-level options override that base.
		tuicSettings := make(map[string]interface{})
		for key, value := range object(settings["server"]) {
			tuicSettings[key] = value
		}
		for key, value := range settings {
			tuicSettings[key] = value
		}
		id, password := stringField(client, "id", "uuid"), stringField(client, "password", "secret")
		if id == "" || password == "" {
			return ""
		}
		user = url.UserPassword(id, password)
		params = map[string]string{"congestion_control": "bbr", "alpn": "h3", "allow_insecure": "0"}
		for _, key := range []string{"sni", "congestion_control", "udp_relay_mode"} {
			if value := stringField(tuicSettings, key); value != "" {
				params[key] = value
			}
		}
		if alpn := stringList(tuicSettings["alpn"]); alpn != "" {
			params["alpn"] = alpn
		}
	case model.MTProto:
		if stringField(client, "secret") == "" {
			return ""
		}
	default:
		return ""
	}
	if user != nil && user.Username() == "" {
		return ""
	}
	endpoints, _ := stream["externalProxy"].([]interface{})
	if len(endpoints) == 0 {
		endpoints = []interface{}{map[string]interface{}{"dest": s.address, "port": float64(inbound.Port), "forceTls": "same", "remark": ""}}
	}
	links := make([]string, 0, len(endpoints))
	for _, item := range endpoints {
		endpoint := object(item)
		host, port := stringField(endpoint, "dest"), inbound.Port
		if value, ok := endpoint["port"].(float64); ok {
			port = int(value)
		}
		if host == "" || port < 1 || port > 65535 {
			continue
		}
		query := url.Values{}
		for key, value := range params {
			if value != "" {
				query.Set(key, value)
			}
		}
		if force := stringField(endpoint, "forceTls"); force == "tls" || force == "none" {
			if inbound.Protocol != model.Hysteria && inbound.Protocol != model.TUIC && inbound.Protocol != model.MTProto {
				query.Set("security", force)
				if force == "none" {
					for _, key := range []string{"sni", "alpn", "fp", "ech", "vcn", "pcs", "pbk", "pqv", "sid", "spx"} {
						query.Del(key)
					}
					if query.Get("encryption") == "none" || query.Get("encryption") == "" {
						query.Del("flow")
					}
				}
			}
		}
		for _, key := range []string{"sni", "alpn"} {
			if value := stringList(endpoint[key]); value != "" {
				query.Set(key, value)
			}
		}
		remark := s.genRemark(inbound, email, stringField(endpoint, "remark"))
		link := url.URL{Scheme: scheme, User: user, Host: joinHostPort(host, port), RawQuery: query.Encode(), Fragment: remark}
		if inbound.Protocol == model.MTProto {
			link = url.URL{Scheme: "tg", Host: "proxy", Fragment: remark}
			link.RawQuery = url.Values{"server": {strings.Trim(host, "[]")}, "port": {strconv.Itoa(port)}, "secret": {stringField(client, "secret")}}.Encode()
		}
		if inbound.Protocol == model.VMESS {
			vmess := map[string]interface{}{"v": "2", "add": strings.Trim(host, "[]"), "port": port, "id": stringField(client, "id"), "scy": stringField(client, "security"), "ps": remark, "net": query.Get("type"), "type": "none", "tls": query.Get("security")}
			for _, key := range []string{"path", "host", "sni", "alpn", "fp", "ech", "vcn", "pcs", "mode", "extra", "fm", "authority"} {
				if value := query.Get(key); value != "" {
					vmess[key] = value
				}
			}
			if value := query.Get("headerType"); value != "" {
				vmess["type"] = value
			}
			if query.Get("type") == "kcp" {
				vmess["path"] = query.Get("seed")
			} else if query.Get("type") == "grpc" {
				vmess["path"] = query.Get("serviceName")
				if query.Get("mode") == "multi" {
					vmess["type"] = "multi"
				}
			}
			encoded, _ := json.Marshal(vmess)
			links = append(links, "vmess://"+base64.StdEncoding.EncodeToString(encoded))
		} else {
			links = append(links, link.String())
		}
	}
	return strings.Join(links, "\n")
}
