package sub

import (
	"encoding/json"

	"x-ui/database/model"
	"x-ui/util/json_util"
)

func hasTransportMux(raw json_util.RawMessage) bool {
	stream := jsonObject(string(raw))
	settings := object(stream["xhttpSettings"])
	_, exists := settings["xmux"]
	return exists || stream["network"] == "xdrive"
}

func (s *SubJsonService) genQUIC(inbound *model.Inbound, stream map[string]interface{}, client model.Client) json_util.RawMessage {
	settings := map[string]interface{}{"address": inbound.Listen, "port": inbound.Port}
	stream["security"] = "tls"
	if inbound.Protocol == model.Hysteria {
		auth := client.Auth
		if auth == "" {
			auth = client.Password
		}
		if auth == "" {
			auth = client.Secret
		}
		if auth == "" {
			return nil
		}
		settings["version"] = 2
		original := object(stream["hysteriaSettings"])
		hy := map[string]interface{}{"version": 2, "auth": auth}
		for _, key := range []string{"udpIdleTimeout", "masquerade"} {
			if value, ok := original[key]; ok {
				hy[key] = value
			}
		}
		stream["network"] = "hysteria"
		stream["hysteriaSettings"] = hy
	} else {
		if client.Password == "" {
			return nil
		}
		masque := map[string]interface{}{"user": client.Email, "pass": client.Password}
		if path := stringField(object(stream["masqueSettings"]), "path"); path != "" {
			masque["path"] = path
		}
		if xmux, ok := object(stream["masqueSettings"])["xmux"].(map[string]interface{}); ok {
			masque["xmux"] = xmux
		}
		stream["network"] = "masque"
		stream["masqueSettings"] = masque
	}
	streamSettings, _ := json.Marshal(stream)
	outbound := Outbound{Protocol: string(inbound.Protocol), Tag: "proxy", Settings: settings, StreamSettings: streamSettings}
	result, _ := json.Marshal(outbound)
	return result
}
