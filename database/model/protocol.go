package model

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// coreProtocolSettings keeps client-side and panel-only fields in SQLite while
// emitting only active users and server credentials to Xray, including hot adds.
func coreProtocolSettings(protocol Protocol, raw string) string {
	var settings map[string]interface{}
	if json.Unmarshal([]byte(raw), &settings) != nil || settings == nil {
		return raw
	}
	if protocol == VLESS {
		delete(settings, "encryption")
	}
	if protocol == Tunnel || protocol == DOKODEMO {
		for old, modern := range map[string]string{"address": "rewriteAddress", "port": "rewritePort", "network": "allowedNetwork"} {
			if _, exists := settings[modern]; !exists {
				if value, ok := settings[old]; ok {
					settings[modern] = value
				}
			}
			delete(settings, old)
		}
	}
	if protocol == WireGuard {
		if peers, ok := settings["peers"].([]interface{}); ok {
			for _, item := range peers {
				peer, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				if public, _ := peer["publicKey"].(string); public == "" {
					if private, _ := peer["privateKey"].(string); private != "" {
						key, err := decodeWireguardKey(private)
						if err == nil {
							if k, err := ecdh.X25519().NewPrivateKey(key); err == nil {
								peer["publicKey"] = base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
							}
						}
					}
				}
				delete(peer, "privateKey")
			}
		}
	}
	if protocol == Hysteria {
		settings["version"] = 2
	}
	if protocol == Masque {
		if _, present := settings["address"]; !present {
			settings["address"] = []string{"10.14.0.1/24", "fd14::1/64"}
		}
	}
	if clients, ok := settings["clients"].([]interface{}); ok {
		active := make([]interface{}, 0, len(clients))
		for _, item := range clients {
			client, ok := item.(map[string]interface{})
			if !ok || client["enable"] == false {
				continue
			}
			for _, key := range []string{"enable", "subId", "limitIp", "totalGB", "expiryTime", "tgId", "reset"} {
				delete(client, key)
			}
			switch protocol {
			case Hysteria:
				if auth, _ := client["auth"].(string); auth == "" {
					for _, key := range []string{"password", "secret"} {
						if value, _ := client[key].(string); value != "" {
							client["auth"] = value
							break
						}
					}
				}
				delete(client, "password")
				delete(client, "secret")
			case Masque:
				if password, present := client["password"]; present {
					client["pass"] = password
				}
				delete(client, "password")
			case VMESS:
				delete(client, "security")
			case VLESS:
				if flow, _ := client["flow"].(string); flow != "" {
					client["flow"] = strings.TrimSuffix(flow, "-udp443")
				}
			}
			active = append(active, client)
		}
		settings["clients"] = active
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		return raw
	}
	return string(encoded)
}

func decodeWireguardKey(raw string) ([]byte, error) {
	if len(raw) == 64 {
		return hex.DecodeString(raw)
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.NewReplacer("-", "+", "_", "/").Replace(raw), "="))
}

func hysteriaStreamSettings(raw string) string {
	var stream map[string]interface{}
	if json.Unmarshal([]byte(raw), &stream) != nil || stream == nil {
		return raw
	}
	stream["network"] = "hysteria"
	stream["security"] = "tls"
	settings, _ := stream["hysteriaSettings"].(map[string]interface{})
	if settings == nil {
		settings = map[string]interface{}{}
		stream["hysteriaSettings"] = settings
	}
	settings["version"] = 2
	encoded, err := json.Marshal(stream)
	if err != nil {
		return raw
	}
	return string(encoded)
}

func masqueStreamSettings(raw string) string {
	var stream map[string]interface{}
	if json.Unmarshal([]byte(raw), &stream) != nil || stream == nil {
		return raw
	}
	stream["network"] = "masque"
	stream["security"] = "tls"
	encoded, err := json.Marshal(stream)
	if err != nil {
		return raw
	}
	return string(encoded)
}

func coreInboundStream(raw string) string {
	var stream map[string]interface{}
	if json.Unmarshal([]byte(raw), &stream) != nil || stream == nil {
		return raw
	}
	for _, key := range []string{"externalProxy"} {
		delete(stream, key)
	}
	for _, key := range []string{"tlsSettings", "realitySettings"} {
		if settings, ok := stream[key].(map[string]interface{}); ok {
			delete(settings, "settings")
		}
	}
	if settings, ok := stream["xhttpSettings"].(map[string]interface{}); ok {
		for _, key := range []string{"xmux", "downloadSettings", "scMinPostsIntervalMs", "uplinkChunkSize", "noGRPCHeader"} {
			delete(settings, key)
		}
	}
	if finalmask, ok := stream["finalmask"].(map[string]interface{}); ok {
		if udp, ok := finalmask["udp"].([]interface{}); ok {
			kept := make([]interface{}, 0, len(udp))
			for _, item := range udp {
				mask, _ := item.(map[string]interface{})
				if mask["type"] != "udphop" {
					kept = append(kept, item)
				}
			}
			if len(kept) == 0 {
				delete(finalmask, "udp")
			} else {
				finalmask["udp"] = kept
			}
		}
		if len(finalmask) == 0 {
			delete(stream, "finalmask")
		}
	}
	encoded, err := json.Marshal(stream)
	if err != nil {
		return raw
	}
	return string(encoded)
}
