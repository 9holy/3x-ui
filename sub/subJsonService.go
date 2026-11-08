package sub

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/util/json_util"
	"x-ui/util/random"
	"x-ui/web/service"
	"x-ui/xray"
)

//go:embed default.json
var defaultJson string

type SubJsonService struct {
	configJson       map[string]interface{}
	defaultOutbounds []json_util.RawMessage
	fragment         string
	noises           string
	mux              string

	inboundService service.InboundService
	SubService     *SubService
}

func NewSubJsonService(fragment string, noises string, mux string, rules string, subService *SubService) *SubJsonService {
	var configJson map[string]interface{}
	var defaultOutbounds []json_util.RawMessage
	json.Unmarshal([]byte(defaultJson), &configJson)
	if outboundSlices, ok := configJson["outbounds"].([]interface{}); ok {
		for _, defaultOutbound := range outboundSlices {
			jsonBytes, _ := json.Marshal(defaultOutbound)
			defaultOutbounds = append(defaultOutbounds, jsonBytes)
		}
	}

	if rules != "" {
		var newRules []interface{}
		routing, _ := configJson["routing"].(map[string]interface{})
		defaultRules, _ := routing["rules"].([]interface{})
		json.Unmarshal([]byte(rules), &newRules)
		defaultRules = append(newRules, defaultRules...)
		routing["rules"] = defaultRules
		configJson["routing"] = routing
	}

	if fragment != "" {
		defaultOutbounds = append(defaultOutbounds, json_util.RawMessage(fragment))
	}

	if noises != "" {
		defaultOutbounds = append(defaultOutbounds, json_util.RawMessage(noises))
	}

	return &SubJsonService{
		configJson:       configJson,
		defaultOutbounds: defaultOutbounds,
		fragment:         fragment,
		noises:           noises,
		mux:              mux,
		SubService:       subService,
	}
}

func (s *SubJsonService) GetJson(subId string, host string) (string, string, error) {
	inbounds, err := s.SubService.getInboundsBySubId(subId)
	if err != nil || len(inbounds) == 0 {
		return "", "", err
	}

	var header string
	var traffic xray.ClientTraffic
	var clientTraffics []xray.ClientTraffic
	var configArray []json_util.RawMessage

	// Prepare Inbounds
	for _, inbound := range inbounds {
		clients, err := s.inboundService.GetClients(inbound)
		if err != nil {
			logger.Error("SubJsonService - GetClients: Unable to get clients from inbound")
		}
		if clients == nil {
			continue
		}
		if len(inbound.Listen) > 0 && inbound.Listen[0] == '@' {
			listen, port, streamSettings, err := s.SubService.getFallbackMaster(inbound.Listen, inbound.StreamSettings)
			if err == nil {
				inbound.Listen = listen
				inbound.Port = port
				inbound.StreamSettings = streamSettings
			}
		}

		for _, client := range clients {
			if client.Enable && client.SubID == subId {
				clientTraffics = append(clientTraffics, s.SubService.getClientTraffics(inbound.ClientStats, client.Email))
				newConfigs := s.getConfig(inbound, client, host)
				configArray = append(configArray, newConfigs...)
			}
		}
	}

	if len(configArray) == 0 {
		return "", "", nil
	}

	// Prepare statistics
	for index, clientTraffic := range clientTraffics {
		if index == 0 {
			traffic.Up = clientTraffic.Up
			traffic.Down = clientTraffic.Down
			traffic.Total = clientTraffic.Total
			if clientTraffic.ExpiryTime > 0 {
				traffic.ExpiryTime = clientTraffic.ExpiryTime
			}
		} else {
			traffic.Up += clientTraffic.Up
			traffic.Down += clientTraffic.Down
			if traffic.Total == 0 || clientTraffic.Total == 0 {
				traffic.Total = 0
			} else {
				traffic.Total += clientTraffic.Total
			}
			if clientTraffic.ExpiryTime != traffic.ExpiryTime {
				traffic.ExpiryTime = 0
			}
		}
	}

	// Combile outbounds
	var finalJson []byte
	if len(configArray) == 1 {
		finalJson, _ = json.MarshalIndent(configArray[0], "", "  ")
	} else {
		finalJson, _ = json.MarshalIndent(configArray, "", "  ")
	}

	header = fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)
	return string(finalJson), header, nil
}

func (s *SubJsonService) getConfig(inbound *model.Inbound, client model.Client, host string) []json_util.RawMessage {
	if xray.CheckLegacyStreamSettings(inbound.StreamSettings) != nil {
		return nil
	}
	switch inbound.Protocol {
	case model.VMESS, model.VLESS, model.Trojan, model.Shadowsocks, model.Hysteria, model.Masque:
	default:
		// Sidecars have no Xray outbound. Never turn them into a direct-only
		// subscription that appears valid but bypasses the requested proxy.
		return nil
	}
	var result []json_util.RawMessage
	rawStream := inbound.StreamSettings
	if inbound.Protocol == model.Hysteria || inbound.Protocol == model.Masque {
		stream := jsonObject(rawStream)
		stream["security"] = "tls"
		encoded, _ := json.Marshal(stream)
		rawStream = string(encoded)
	}
	stream := s.streamData(rawStream)
	endpoints, _ := stream["externalProxy"].([]interface{})
	if len(endpoints) == 0 {
		endpoints = []interface{}{map[string]interface{}{
			"forceTls": "same", "dest": host, "port": float64(inbound.Port), "remark": "",
		}}
	}
	delete(stream, "externalProxy")
	for _, item := range endpoints {
		ep := object(item)
		copyInbound := *inbound
		copyInbound.Listen = stringField(ep, "dest")
		if port, ok := ep["port"].(float64); ok {
			copyInbound.Port = int(port)
		}
		if copyInbound.Listen == "" || copyInbound.Port < 1 || copyInbound.Port > 65535 {
			continue
		}
		encoded, _ := json.Marshal(stream)
		newStream := jsonObject(string(encoded))
		if inbound.Protocol != model.Hysteria && inbound.Protocol != model.Masque {
			switch stringField(ep, "forceTls") {
			case "tls":
				newStream["security"] = "tls"
				if _, ok := newStream["tlsSettings"]; !ok {
					newStream["tlsSettings"] = map[string]interface{}{}
				}
				delete(newStream, "realitySettings")
			case "none":
				newStream["security"] = "none"
				delete(newStream, "tlsSettings")
				delete(newStream, "realitySettings")
			}
		}
		if newStream["security"] == "tls" {
			tls := object(newStream["tlsSettings"])
			if sni := stringField(ep, "sni"); sni != "" {
				tls["serverName"] = sni
			}
			if alpn := stringList(ep["alpn"]); alpn != "" {
				tls["alpn"] = strings.Split(alpn, ",")
			}
			newStream["tlsSettings"] = tls
		}
		streamSettings, _ := json.Marshal(newStream)
		var proxy json_util.RawMessage
		switch inbound.Protocol {
		case model.VMESS, model.VLESS:
			proxy = s.genVnext(&copyInbound, streamSettings, client)
		case model.Trojan, model.Shadowsocks:
			proxy = s.genServer(&copyInbound, streamSettings, client)
		case model.Hysteria, model.Masque:
			proxy = s.genQUIC(&copyInbound, newStream, client)
		}
		if len(proxy) == 0 {
			continue
		}
		outbounds := append([]json_util.RawMessage{proxy}, s.defaultOutbounds...)
		config := make(map[string]interface{}, len(s.configJson))
		for key, value := range s.configJson {
			config[key] = value
		}
		config["outbounds"] = outbounds
		config["remarks"] = s.SubService.genRemark(inbound, client.Email, stringField(ep, "remark"))
		configJSON, _ := json.Marshal(config)
		result = append(result, configJSON)
	}
	return result
}

func (s *SubJsonService) streamData(raw string) map[string]interface{} {
	stream := jsonObject(xray.NormalizeStreamSettings(raw))
	switch stream["security"] {
	case "tls":
		stream["tlsSettings"] = s.tlsData(object(stream["tlsSettings"]))
		delete(stream, "realitySettings")
	case "reality":
		stream["realitySettings"] = s.realityData(object(stream["realitySettings"]))
		delete(stream, "tlsSettings")
	default:
		delete(stream, "tlsSettings")
		delete(stream, "realitySettings")
	}
	delete(stream, "xtlsSettings")
	delete(stream, "sockopt")
	if s.fragment != "" {
		stream["sockopt"] = json_util.RawMessage(`{"dialerProxy":"fragment","tcpKeepAliveIdle":100,"tcpMptcp":true,"tcpNoDelay":true}`)
	}
	for _, key := range []string{"tcpSettings", "wsSettings", "httpupgradeSettings"} {
		if settings, ok := stream[key]; ok {
			stream[key] = s.removeAcceptProxy(settings)
		}
	}
	if settings, ok := stream["xhttpSettings"].(map[string]interface{}); ok {
		stream["xhttpSettings"] = clientXHTTPSettings(settings)
	}
	if masks, ok := stream["finalmask"].(map[string]interface{}); ok {
		stream["finalmask"] = clientFinalMask(masks)
	}
	return stream
}

func (s *SubJsonService) removeAcceptProxy(setting interface{}) map[string]interface{} {
	netSettings, ok := setting.(map[string]interface{})
	if ok {
		delete(netSettings, "acceptProxyProtocol")
	}
	return netSettings
}

func (s *SubJsonService) tlsData(tData map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, key := range []string{"serverName", "alpn", "cipherSuites"} {
		if value, ok := tData[key]; ok {
			result[key] = value
		}
	}
	client := object(tData["settings"])
	if len(client) == 0 {
		client = tData
	}
	for _, key := range []string{"fingerprint", "echConfigList"} {
		if value, ok := client[key].(string); ok && value != "" {
			result[key] = value
		}
	}
	if names := stringList(client["verifyPeerCertByName"]); names != "" {
		result["verifyPeerCertByName"] = names
	}
	if pins := stringList(client["pinnedPeerCertSha256"]); pins != "" {
		values := strings.Split(pins, ",")
		for i, pin := range values {
			pin = strings.TrimSpace(pin)
			encoded := strings.TrimRight(strings.NewReplacer("-", "+", "_", "/").Replace(pin), "=")
			if raw, err := base64.RawStdEncoding.DecodeString(encoded); err == nil && len(raw) == 32 {
				pin = hex.EncodeToString(raw)
			}
			values[i] = pin
		}
		result["pinnedPeerCertSha256"] = strings.Join(values, ",")
	}
	return result
}

func (s *SubJsonService) realityData(rData map[string]interface{}) map[string]interface{} {
	rltyData := make(map[string]interface{}, 1)
	rltyClientSettings, _ := rData["settings"].(map[string]interface{})

	rltyData["show"] = false
	rltyData["publicKey"] = stringField(rltyClientSettings, "publicKey", "password")
	rltyData["fingerprint"] = stringField(rltyClientSettings, "fingerprint")
	rltyData["mldsa65Verify"] = stringField(rltyClientSettings, "mldsa65Verify")

	// Set random data
	rltyData["spiderX"] = stringField(rltyClientSettings, "spiderX")
	if rltyData["spiderX"] == "" {
		rltyData["spiderX"] = "/" + random.Seq(15)
	}
	shortIds, ok := rData["shortIds"].([]interface{})
	if ok && len(shortIds) > 0 {
		rltyData["shortId"] = shortIds[random.Num(len(shortIds))].(string)
	} else {
		rltyData["shortId"] = ""
	}
	serverNames, ok := rData["serverNames"].([]interface{})
	if ok && len(serverNames) > 0 {
		rltyData["serverName"] = serverNames[random.Num(len(serverNames))].(string)
	} else {
		rltyData["serverName"] = ""
	}

	return rltyData
}

func (s *SubJsonService) genVnext(inbound *model.Inbound, streamSettings json_util.RawMessage, client model.Client) json_util.RawMessage {
	outbound := Outbound{}
	usersData := make([]UserVnext, 1)

	usersData[0].ID = client.ID
	usersData[0].Level = 8
	if inbound.Protocol == model.VMESS {
		usersData[0].Security = client.Security
	}
	if inbound.Protocol == model.VLESS {
		usersData[0].Encryption = vlessClientEncryption(jsonObject(inbound.Settings))
		stream := jsonObject(string(streamSettings))
		if supportsVLESSFlow(stream, jsonObject(inbound.Settings)) {
			usersData[0].Flow = client.Flow
		}
	}

	vnextData := make([]VnextSetting, 1)
	vnextData[0] = VnextSetting{
		Address: inbound.Listen,
		Port:    inbound.Port,
		Users:   usersData,
	}

	outbound.Protocol = string(inbound.Protocol)
	outbound.Tag = "proxy"
	if s.mux != "" && !hasTransportMux(streamSettings) {
		outbound.Mux = json_util.RawMessage(s.mux)
	}
	outbound.StreamSettings = streamSettings
	outbound.Settings = OutboundSettings{
		Vnext: vnextData,
	}

	result, _ := json.MarshalIndent(outbound, "", "  ")
	return result
}

func (s *SubJsonService) genServer(inbound *model.Inbound, streamSettings json_util.RawMessage, client model.Client) json_util.RawMessage {
	outbound := Outbound{}

	serverData := make([]ServerSetting, 1)
	serverData[0] = ServerSetting{
		Address:  inbound.Listen,
		Port:     inbound.Port,
		Level:    8,
		Password: client.Password,
	}

	if inbound.Protocol == model.Shadowsocks {
		var inboundSettings map[string]interface{}
		json.Unmarshal([]byte(inbound.Settings), &inboundSettings)
		method, _ := inboundSettings["method"].(string)
		serverData[0].Method = method

		// server password in multi-user 2022 protocols
		if strings.HasPrefix(method, "2022") {
			if serverPassword, ok := inboundSettings["password"].(string); ok {
				serverData[0].Password = fmt.Sprintf("%s:%s", serverPassword, client.Password)
			}
		}
	}

	outbound.Protocol = string(inbound.Protocol)
	outbound.Tag = "proxy"
	if s.mux != "" && !hasTransportMux(streamSettings) {
		outbound.Mux = json_util.RawMessage(s.mux)
	}
	outbound.StreamSettings = streamSettings
	outbound.Settings = OutboundSettings{
		Servers: serverData,
	}

	result, _ := json.MarshalIndent(outbound, "", "  ")
	return result
}

type Outbound struct {
	Protocol       string                 `json:"protocol"`
	Tag            string                 `json:"tag"`
	StreamSettings json_util.RawMessage   `json:"streamSettings"`
	Mux            json_util.RawMessage   `json:"mux,omitempty"`
	ProxySettings  map[string]interface{} `json:"proxySettings,omitempty"`
	Settings       interface{}            `json:"settings,omitempty"`
}

type OutboundSettings struct {
	Vnext   []VnextSetting  `json:"vnext,omitempty"`
	Servers []ServerSetting `json:"servers,omitempty"`
}

type VnextSetting struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []UserVnext `json:"users"`
}

type UserVnext struct {
	Encryption string `json:"encryption,omitempty"`
	Flow       string `json:"flow,omitempty"`
	ID         string `json:"id"`
	Security   string `json:"security,omitempty"`
	Level      int    `json:"level"`
}

type ServerSetting struct {
	Password string `json:"password"`
	Level    int    `json:"level"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Flow     string `json:"flow,omitempty"`
	Method   string `json:"method,omitempty"`
}
