package xray

import (
	"encoding/json"
	"fmt"
)

// NormalizeStreamSettings upgrades legacy wire formats without rewriting the
// stored inbound. Both the native core and subscriptions must see the same masks.
func NormalizeStreamSettings(raw string) string {
	var stream map[string]interface{}
	if json.Unmarshal([]byte(raw), &stream) != nil || stream == nil {
		return raw
	}
	NormalizeStream(stream)
	encoded, err := json.Marshal(stream)
	if err != nil {
		return raw
	}
	return string(encoded)
}

func NormalizeStream(stream map[string]interface{}) {
	if stream == nil {
		return
	}
	switch stream["network"] {
	case "raw":
		stream["network"] = "tcp"
		if settings, ok := stream["rawSettings"]; ok {
			if _, present := stream["tcpSettings"]; !present {
				stream["tcpSettings"] = settings
			}
			delete(stream, "rawSettings")
		}
	case "splithttp":
		stream["network"] = "xhttp"
		if settings, ok := stream["splithttpSettings"]; ok {
			if _, present := stream["xhttpSettings"]; !present {
				stream["xhttpSettings"] = settings
			}
			delete(stream, "splithttpSettings")
		}
	}
	if settings, ok := stream["xhttpSettings"].(map[string]interface{}); ok {
		if extra, ok := settings["extra"].(map[string]interface{}); ok {
			for key, value := range extra {
				if _, present := settings[key]; !present {
					settings[key] = value
				}
			}
			delete(settings, "extra")
		}
		for old, current := range map[string]string{"sessionPlacement": "sessionIDPlacement", "sessionKey": "sessionIDKey"} {
			if value, ok := settings[old]; ok {
				if _, present := settings[current]; !present {
					settings[current] = value
				}
				delete(settings, old)
			}
		}
	}
	if stream["network"] == "kcp" {
		normalizeKCP(stream)
	}
	if stream["network"] == "hysteria" {
		normalizeHysteria(stream)
	}
	normalizeUDPHop(stream)
}

// NormalizeConfigProtocols also covers outbounds already stored in the Xray
// template, so an upgrade does not require opening and resaving every editor.
func NormalizeConfigProtocols(config *Config) {
	var outbounds []map[string]interface{}
	if json.Unmarshal(config.OutboundConfigs, &outbounds) != nil {
		return
	}
	for _, outbound := range outbounds {
		stream, _ := outbound["streamSettings"].(map[string]interface{})
		if outbound["protocol"] == "hysteria" {
			if stream == nil {
				stream = map[string]interface{}{}
				outbound["streamSettings"] = stream
			}
			stream["network"] = "hysteria"
			stream["security"] = "tls"
			settings, _ := outbound["settings"].(map[string]interface{})
			if settings == nil {
				settings = map[string]interface{}{}
				outbound["settings"] = settings
			}
			settings["version"] = 2
		}
		NormalizeStream(stream)
	}
	if encoded, err := json.Marshal(outbounds); err == nil {
		config.OutboundConfigs = encoded
	}
}

func normalizeHysteria(stream map[string]interface{}) {
	hy, _ := stream["hysteriaSettings"].(map[string]interface{})
	if hy == nil {
		hy = map[string]interface{}{}
		stream["hysteriaSettings"] = hy
	}
	hy["version"] = 2
	fm, _ := stream["finalmask"].(map[string]interface{})
	if fm == nil {
		fm = map[string]interface{}{}
	}
	if legacy, ok := hy["finalmask"].(map[string]interface{}); ok {
		for key, value := range legacy {
			if _, exists := fm[key]; !exists {
				fm[key] = value
			}
		}
		delete(hy, "finalmask")
	}
	quic, _ := fm["quicParams"].(map[string]interface{})
	if quic == nil {
		quic = map[string]interface{}{}
	}
	for _, key := range []string{"initStreamReceiveWindow", "maxStreamReceiveWindow", "initConnectionReceiveWindow", "maxConnectionReceiveWindow", "maxIdleTimeout", "keepAlivePeriod", "disablePathMTUDiscovery"} {
		if value, exists := hy[key]; exists {
			if _, present := quic[key]; !present && fmt.Sprint(value) != "0" {
				quic[key] = value
			}
			delete(hy, key)
		}
	}
	for old, current := range map[string]string{"up": "brutalUp", "down": "brutalDown"} {
		value, exists := hy[old]
		if !exists {
			value, exists = quic[old]
		}
		if exists && fmt.Sprint(value) != "0" && fmt.Sprint(value) != "" {
			if _, present := quic[current]; !present {
				quic[current] = fmt.Sprint(value)
			}
			if _, present := quic["congestion"]; !present {
				quic["congestion"] = "brutal"
			}
		}
		delete(hy, old)
		delete(quic, old)
	}
	if legacy, ok := hy["udphop"].(map[string]interface{}); ok {
		if _, present := quic["udpHop"]; !present {
			port, _ := legacy["port"].(string)
			if port != "" {
				hop := map[string]interface{}{"ports": port}
				if interval, ok := legacy["interval"]; ok {
					hop["interval"] = fmt.Sprint(interval)
				}
				quic["udpHop"] = hop
			}
		}
		delete(hy, "udphop")
	}
	if len(quic) > 0 {
		fm["quicParams"] = quic
	}
	if len(fm) > 0 {
		stream["finalmask"] = fm
	}
}

func normalizeKCP(stream map[string]interface{}) {
	kcp, _ := stream["kcpSettings"].(map[string]interface{})
	if kcp == nil {
		return
	}
	fm, _ := stream["finalmask"].(map[string]interface{})
	if fm == nil {
		fm = map[string]interface{}{}
	}
	masks, _ := fm["udp"].([]interface{})
	hasSeed, hasHeader := false, false
	for _, item := range masks {
		mask, _ := item.(map[string]interface{})
		if mask["type"] != "mkcp-legacy" {
			continue
		}
		settings, _ := mask["settings"].(map[string]interface{})
		header, _ := settings["header"].(string)
		if header == "" {
			hasSeed = true
		} else {
			hasHeader = true
		}
	}
	legacy := false
	for _, key := range []string{"seed", "header", "congestion", "readBufferSize", "writeBufferSize"} {
		if _, exists := kcp[key]; exists {
			legacy = true
		}
	}
	seed, _ := kcp["seed"].(string)
	if legacy && !hasSeed {
		masks = append(masks, map[string]interface{}{"type": "mkcp-legacy", "settings": map[string]interface{}{"header": "", "value": seed}})
	}
	header, _ := kcp["header"].(map[string]interface{})
	if name, ok := header["type"].(string); ok && name != "" && name != "none" && !hasHeader {
		if name == "wechat-video" {
			name = "wechat"
		}
		masks = append(masks, map[string]interface{}{"type": "mkcp-legacy", "settings": map[string]interface{}{"header": name}})
	}
	if len(masks) > 0 {
		fm["udp"] = masks
		stream["finalmask"] = fm
	}
	for _, key := range []string{"seed", "header", "congestion", "readBufferSize", "writeBufferSize"} {
		delete(kcp, key)
	}
}

// CheckLegacyStreamSettings flags wire formats that cannot be converted
// transparently. Operators must update both endpoints for these migrations.
func CheckLegacyStreamSettings(raw string) error {
	var stream map[string]interface{}
	if json.Unmarshal([]byte(raw), &stream) != nil {
		return nil // Native validation returns the detailed JSON error.
	}
	switch stream["network"] {
	case "http", "quic":
		return fmt.Errorf("Xray 26.10.31 no longer supports %v transport; migrate the server and clients to XHTTP and refresh subscriptions", stream["network"])
	case "kcp":
		kcp, _ := stream["kcpSettings"].(map[string]interface{})
		if seed, present := kcp["seed"].(string); present && seed == "" {
			return fmt.Errorf("legacy mKCP with an explicit empty seed cannot be migrated transparently; set a nonempty seed and update the clients")
		}
	}
	return nil
}

func normalizeUDPHop(stream map[string]interface{}) {
	fm, _ := stream["finalmask"].(map[string]interface{})
	if fm == nil {
		return
	}
	masks, _ := fm["udp"].([]interface{})
	var hop interface{}
	kept := make([]interface{}, 0, len(masks)+1)
	for _, item := range masks {
		mask, _ := item.(map[string]interface{})
		if mask["type"] == "udphop" {
			hop = item
		} else {
			kept = append(kept, item)
		}
	}
	quic, _ := fm["quicParams"].(map[string]interface{})
	if legacy, ok := quic["udpHop"].(map[string]interface{}); ok {
		if ports, ok := legacy["ports"].(string); ok && ports != "" && hop == nil {
			settings := map[string]interface{}{"mode": "intervalRemote", "remotePorts": ports}
			if interval, ok := legacy["interval"]; ok {
				settings["interval"] = fmt.Sprint(interval)
			}
			hop = map[string]interface{}{"type": "udphop", "settings": settings}
		}
		delete(quic, "udpHop")
		if len(quic) == 0 {
			delete(fm, "quicParams")
		}
	}
	if hop != nil {
		// The mask that owns the UDP socket must be last.
		fm["udp"] = append(kept, hop)
	}
}
