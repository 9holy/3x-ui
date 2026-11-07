package sub

import (
	"fmt"
	"strings"
	"time"

	"x-ui/database"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/util/common"
	"x-ui/web/service"
	"x-ui/xray"

	"github.com/goccy/go-json"
)

type SubService struct {
	address        string
	showInfo       bool
	remarkModel    string
	datepicker     string
	inboundService service.InboundService
	settingService service.SettingService
}

func NewSubService(showInfo bool, remarkModel string) *SubService {
	return &SubService{
		showInfo:    showInfo,
		remarkModel: remarkModel,
	}
}

func (s *SubService) GetSubs(subId string, host string) ([]string, string, error) {
	// A controller shares the service across requests. Keep the host and
	// datepicker request-local so concurrent subscriptions cannot cross hosts.
	request := *s
	s = &request
	s.address = host
	var result []string
	var header string
	var traffic xray.ClientTraffic
	var clientTraffics []xray.ClientTraffic
	inbounds, err := s.getInboundsBySubId(subId)
	if err != nil {
		return nil, "", err
	}

	if len(inbounds) == 0 {
		return nil, "", common.NewError("No inbounds found with ", subId)
	}

	s.datepicker, err = s.settingService.GetDatepicker()
	if err != nil {
		s.datepicker = "gregorian"
	}
	for _, inbound := range inbounds {
		clients, err := s.inboundService.GetClients(inbound)
		if err != nil {
			logger.Error("SubService - GetClients: Unable to get clients from inbound")
		}
		if clients == nil {
			continue
		}
		if len(inbound.Listen) > 0 && inbound.Listen[0] == '@' {
			listen, port, streamSettings, err := s.getFallbackMaster(inbound.Listen, inbound.StreamSettings)
			if err == nil {
				inbound.Listen = listen
				inbound.Port = port
				inbound.StreamSettings = streamSettings
			}
		}
		for _, client := range clients {
			if client.Enable && client.SubID == subId {
				link := s.getLink(inbound, client.Email)
				if link != "" {
					result = append(result, link)
				}
				clientTraffics = append(clientTraffics, s.getClientTraffics(inbound.ClientStats, client.Email))
			}
		}
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
	header = fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)
	return result, header, nil
}

func (s *SubService) getInboundsBySubId(subId string) ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Preload("ClientStats").Where(`id in (
		SELECT DISTINCT inbounds.id
		FROM inbounds,
			JSON_EACH(JSON_EXTRACT(inbounds.settings, '$.clients')) AS client 
		WHERE
			protocol in ('vmess','vless','trojan','shadowsocks','hysteria','tuic','mtproto','masque')
			AND JSON_EXTRACT(client.value, '$.subId') = ? AND enable = ?
	)`, subId, true).Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	return inbounds, nil
}

func (s *SubService) getClientTraffics(traffics []xray.ClientTraffic, email string) xray.ClientTraffic {
	for _, traffic := range traffics {
		if traffic.Email == email {
			return traffic
		}
	}
	return xray.ClientTraffic{}
}

func (s *SubService) getFallbackMaster(dest string, streamSettings string) (string, int, string, error) {
	db := database.GetDB()
	var inbound *model.Inbound
	err := db.Model(model.Inbound{}).
		Where("JSON_TYPE(settings, '$.fallbacks') = 'array'").
		Where("EXISTS (SELECT * FROM json_each(settings, '$.fallbacks') WHERE json_extract(value, '$.dest') = ?)", dest).
		Find(&inbound).Error
	if err != nil {
		return "", 0, "", err
	}

	var stream map[string]interface{}
	json.Unmarshal([]byte(streamSettings), &stream)
	var masterStream map[string]interface{}
	json.Unmarshal([]byte(inbound.StreamSettings), &masterStream)
	stream["security"] = masterStream["security"]
	stream["tlsSettings"] = masterStream["tlsSettings"]
	stream["externalProxy"] = masterStream["externalProxy"]
	modifiedStream, _ := json.MarshalIndent(stream, "", "  ")

	return inbound.Listen, inbound.Port, string(modifiedStream), nil
}

func (s *SubService) getLink(inbound *model.Inbound, email string) string {
	switch inbound.Protocol {
	case "vmess":
		return s.genVmessLink(inbound, email)
	case "vless":
		return s.genVlessLink(inbound, email)
	case "trojan":
		return s.genTrojanLink(inbound, email)
	case "shadowsocks":
		return s.genShadowsocksLink(inbound, email)
	case "hysteria", "tuic", "mtproto", "amneziawg", "masque", "tun":
		return s.genProtocolLink(inbound, email)
	}
	return ""
}

func (s *SubService) genProtocolLink(inbound *model.Inbound, email string) string {
	return s.protocolShareLinks(inbound, email)
}

func (s *SubService) genVmessLink(inbound *model.Inbound, email string) string {
	return s.protocolShareLinks(inbound, email)
}

func (s *SubService) genVlessLink(inbound *model.Inbound, email string) string {
	return s.protocolShareLinks(inbound, email)
}

func (s *SubService) genTrojanLink(inbound *model.Inbound, email string) string {
	return s.protocolShareLinks(inbound, email)
}

func (s *SubService) genShadowsocksLink(inbound *model.Inbound, email string) string {
	return s.protocolShareLinks(inbound, email)
}

func (s *SubService) genRemark(inbound *model.Inbound, email string, extra string) string {
	remarkModel := s.remarkModel
	if remarkModel == "" {
		remarkModel = "-ieo"
	}
	separationChar := string(remarkModel[0])
	orderChars := remarkModel[1:]
	orders := map[byte]string{
		'i': "",
		'e': "",
		'o': "",
	}
	if len(email) > 0 {
		orders['e'] = email
	}
	if len(inbound.Remark) > 0 {
		orders['i'] = inbound.Remark
	}
	if len(extra) > 0 {
		orders['o'] = extra
	}

	var remark []string
	for i := 0; i < len(orderChars); i++ {
		char := orderChars[i]
		order, exists := orders[char]
		if exists && order != "" {
			remark = append(remark, order)
		}
	}

	if s.showInfo {
		statsExist := false
		var stats xray.ClientTraffic
		for _, clientStat := range inbound.ClientStats {
			if clientStat.Email == email {
				stats = clientStat
				statsExist = true
				break
			}
		}

		// Get remained days
		if statsExist {
			if !stats.Enable {
				return fmt.Sprintf("⛔️N/A%s%s", separationChar, strings.Join(remark, separationChar))
			}
			if vol := stats.Total - (stats.Up + stats.Down); vol > 0 {
				remark = append(remark, fmt.Sprintf("%s%s", common.FormatTraffic(vol), "📊"))
			}
			now := time.Now().Unix()
			switch exp := stats.ExpiryTime / 1000; {
			case exp > 0:
				remainingSeconds := exp - now
				days := remainingSeconds / 86400
				hours := (remainingSeconds % 86400) / 3600
				minutes := (remainingSeconds % 3600) / 60
				if days > 0 {
					if hours > 0 {
						remark = append(remark, fmt.Sprintf("%dD,%dH⏳", days, hours))
					} else {
						remark = append(remark, fmt.Sprintf("%dD⏳", days))
					}
				} else if hours > 0 {
					remark = append(remark, fmt.Sprintf("%dH⏳", hours))
				} else {
					remark = append(remark, fmt.Sprintf("%dM⏳", minutes))
				}
			case exp < 0:
				days := exp / -86400
				hours := (exp % -86400) / 3600
				minutes := (exp % -3600) / 60
				if days > 0 {
					if hours > 0 {
						remark = append(remark, fmt.Sprintf("%dD,%dH⏳", days, hours))
					} else {
						remark = append(remark, fmt.Sprintf("%dD⏳", days))
					}
				} else if hours > 0 {
					remark = append(remark, fmt.Sprintf("%dH⏳", hours))
				} else {
					remark = append(remark, fmt.Sprintf("%dM⏳", minutes))
				}
			}
		}
	}
	return strings.Join(remark, separationChar)
}

func searchKey(data interface{}, key string) (interface{}, bool) {
	switch val := data.(type) {
	case map[string]interface{}:
		for k, v := range val {
			if k == key {
				return v, true
			}
			if result, ok := searchKey(v, key); ok {
				return result, true
			}
		}
	case []interface{}:
		for _, v := range val {
			if result, ok := searchKey(v, key); ok {
				return result, true
			}
		}
	}
	return nil, false
}

func searchHost(headers interface{}) string {
	data, _ := headers.(map[string]interface{})
	for k, v := range data {
		if strings.EqualFold(k, "host") {
			switch v.(type) {
			case []interface{}:
				hosts, _ := v.([]interface{})
				if len(hosts) > 0 {
					return hosts[0].(string)
				} else {
					return ""
				}
			case interface{}:
				return v.(string)
			}
		}
	}

	return ""
}
