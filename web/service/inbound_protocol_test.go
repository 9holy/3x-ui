package service

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"x-ui/database"
	"x-ui/database/model"
	"x-ui/xray"
)

const fixtureSecret = "ee0123456789abcdef0123456789abcdef6578616d706c652e636f6d"

func protocolDB(t *testing.T) *InboundService {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "panel.db")); err != nil {
		t.Fatal(err)
	}
	oldProcess := p
	p = nil
	t.Cleanup(func() { p = oldProcess; _ = database.CloseDB() })
	return &InboundService{}
}

func mtprotoFixture(email string, port int) *model.Inbound {
	return &model.Inbound{Protocol: model.MTProto, Port: port, Tag: fmt.Sprintf("inbound-%d", port), Settings: fmt.Sprintf(`{"clients":[{"email":%q,"secret":%q,"enable":true}]}`, email, fixtureSecret), StreamSettings: `{}`}
}

func TestMTProtoClientCRUDDoesNotRequireAnXrayUUIDOrRunningCore(t *testing.T) {
	service := protocolDB(t)
	inbound, restart, err := service.AddInbound(mtprotoFixture("first", 23456))
	if err != nil || restart {
		t.Fatalf("add inbound: %v restart=%v", err, restart)
	}
	second := strings.Replace(fixtureSecret, "0123456789abcdef", "1123456789abcdef", 1)
	data := &model.Inbound{Id: inbound.Id, Settings: fmt.Sprintf(`{"clients":[{"email":"second","secret":%q,"enable":true}]}`, second)}
	if restart, err := service.AddInboundClient(data); err != nil || restart {
		t.Fatalf("add client: %v restart=%v", err, restart)
	}
	data.Settings = fmt.Sprintf(`{"clients":[{"email":"renamed","secret":%q,"enable":false}]}`, second)
	if restart, err := service.UpdateInboundClient(data, "second"); err != nil || restart {
		t.Fatalf("update client: %v restart=%v", err, restart)
	}
	saved, err := service.GetInbound(inbound.Id)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := service.GetClients(saved)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 || clients[1].Email != "renamed" || clients[1].Enable {
		t.Fatalf("client update was not persisted: %+v", clients)
	}
	if restart, err := service.DelInboundClient(inbound.Id, "renamed"); err != nil || restart {
		t.Fatalf("delete client: %v restart=%v", err, restart)
	}
	var remaining int64
	if err := database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", "renamed").Count(&remaining).Error; err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("deleted client's statistics remain")
	}
}

func TestNewProtocolClientAliasesAndIdentifiers(t *testing.T) {
	service := &InboundService{}
	tests := []struct {
		protocol             model.Protocol
		settings, identifier string
	}{
		{model.Hysteria, `{"version":2,"clients":[{"email":"hy","auth":"auth-value"}]}`, "auth-value"},
		{model.Masque, `{"address":["10.14.0.1/24"],"clients":[{"email":"masque","pass":"pass-value"}]}`, "pass-value"},
		{model.TUIC, `{"server":{"certificate":"cert"},"clients":[{"email":"tuic","uuid":"11111111-2222-3333-4444-555555555555","password":"pass-value"}]}`, "tuic"},
	}
	for _, tt := range tests {
		t.Run(string(tt.protocol), func(t *testing.T) {
			clients, err := service.GetClients(&model.Inbound{Protocol: tt.protocol, Settings: tt.settings})
			if err != nil || len(clients) != 1 {
				t.Fatalf("mixed settings/client parse: %+v, %v", clients, err)
			}
			if err := validateClientCredentials(tt.protocol, clients); err != nil {
				t.Fatal(err)
			}
			if got := clientIdentifier(tt.protocol, clients[0]); got != tt.identifier {
				t.Fatalf("identifier=%q, want %q", got, tt.identifier)
			}
		})
	}
}

func TestMTProtoAccountingUpdatesInboundAndDisablesDepletedClientWithoutXray(t *testing.T) {
	service := protocolDB(t)
	inbound := mtprotoFixture("metered", 23457)
	inbound.Settings = strings.Replace(inbound.Settings, `"enable":true`, `"enable":true,"totalGB":10`, 1)
	if _, _, err := service.AddInbound(inbound); err != nil {
		t.Fatal(err)
	}
	err, restart := service.AddTraffic([]*xray.Traffic{{Tag: inbound.Tag, IsInbound: true, Up: 4, Down: 7}}, []*xray.ClientTraffic{{InboundId: inbound.Id, Email: "metered", Up: 4, Down: 7}})
	if err != nil || restart {
		t.Fatalf("accounting failed: %v restart=%v", err, restart)
	}
	stat, err := service.GetClientTrafficByEmail("metered")
	if err != nil {
		t.Fatal(err)
	}
	if stat.Enable || stat.Up != 4 || stat.Down != 7 {
		t.Fatalf("quota/traffic state: %+v", stat)
	}
	saved, err := service.GetInbound(inbound.Id)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Up != 4 || saved.Down != 7 {
		t.Fatal("inbound traffic totals were lost")
	}
	if restart, err := service.ResetClientTraffic(inbound.Id, "metered"); err != nil || restart {
		t.Fatalf("sidecar quota reset: %v restart=%v", err, restart)
	}
}

func TestRawInboundEditUpdatesClientLimitsAndExpiry(t *testing.T) {
	service := protocolDB(t)
	inbound := mtprotoFixture("raw-edit", 23458)
	if _, _, err := service.AddInbound(inbound); err != nil {
		t.Fatal(err)
	}
	inbound.Settings = strings.Replace(inbound.Settings, `"enable":true`, `"enable":true,"totalGB":1234,"expiryTime":1999999999999`, 1)
	if _, restart, err := service.UpdateInbound(inbound); err != nil || restart {
		t.Fatalf("raw edit: %v restart=%v", err, restart)
	}
	stat, err := service.GetClientTrafficByEmail("raw-edit")
	if err != nil {
		t.Fatal(err)
	}
	if stat.Total != 1234 || stat.ExpiryTime != 1999999999999 {
		t.Fatalf("raw edit left stale limits: %+v", stat)
	}
}

func TestInboundCreationRollsBackWhenClientStatisticsCannotBeStored(t *testing.T) {
	service := protocolDB(t)
	if err := database.GetDB().Create(&xray.ClientTraffic{Email: "orphan"}).Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AddInbound(mtprotoFixture("orphan", 23459)); err == nil {
		t.Fatal("statistics failure was reported as successful creation")
	}
	var count int64
	if err := database.GetDB().Model(model.Inbound{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed creation left an unmetered inbound behind")
	}
}

func TestGetXrayConfigPreservesModernCredentialsAndOmitsSidecars(t *testing.T) {
	protocolDB(t)
	fixtures := []*model.Inbound{
		{Protocol: model.Hysteria, Enable: true, Port: 28001, Tag: "hy", Settings: `{"clients":[{"email":"hy","auth":"hy-secret","enable":true}]}`, StreamSettings: `{"network":"hysteria","security":"tls"}`},
		{Protocol: model.Masque, Enable: true, Port: 28002, Tag: "masque", Settings: `{"clients":[{"email":"masque","password":"masque-secret","enable":true}]}`, StreamSettings: `{"network":"masque","security":"tls"}`},
		{Protocol: model.MTProto, Enable: true, Port: 28003, Tag: "mtproto", Settings: fmt.Sprintf(`{"clients":[{"email":"mt","secret":%q}]}`, fixtureSecret)},
		{Protocol: model.TUIC, Enable: true, Port: 28004, Tag: "tuic", Settings: `{}`},
		{Protocol: model.AmneziaWG, Enable: true, Port: 28005, Tag: "awg", Settings: `{}`},
	}
	for _, inbound := range fixtures {
		if err := database.GetDB().Create(inbound).Error; err != nil {
			t.Fatal(err)
		}
	}
	config, err := (&XrayService{}).GetXrayConfig()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, inbound := range config.InboundConfigs {
		if inbound.Tag != "hy" && inbound.Tag != "masque" {
			if inbound.Tag == "mtproto" || inbound.Tag == "tuic" || inbound.Tag == "awg" {
				t.Fatalf("sidecar %s leaked into Xray", inbound.Tag)
			}
			continue
		}
		var settings map[string]interface{}
		if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
			t.Fatal(err)
		}
		client := settings["clients"].([]interface{})[0].(map[string]interface{})
		if inbound.Tag == "hy" && client["auth"] != "hy-secret" {
			t.Fatalf("Hysteria auth stripped: %+v", client)
		}
		if inbound.Tag == "masque" && client["pass"] != "masque-secret" {
			t.Fatalf("MASQUE password stripped: %+v", client)
		}
		seen[inbound.Tag] = true
	}
	if !seen["hy"] || !seen["masque"] {
		t.Fatal("modern core inbound omitted")
	}
}

func TestModernProtocolRequiresNativeValidationBeforeSave(t *testing.T) {
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())
	modern := &model.Inbound{Protocol: model.Hysteria, Enable: true, Port: 443, Settings: `{"clients":[{"email":"test","auth":"secret"}]}`, StreamSettings: `{"network":"hysteria","security":"tls"}`}
	if err := validateProtocolSettings(modern); err == nil {
		t.Fatal("new protocol accepted without the native runtime")
	}
	legacy := &model.Inbound{Protocol: model.VLESS, Enable: true, Port: 443, Settings: `{"decryption":"none","clients":[{"id":"11111111-2222-3333-4444-555555555555"}]}`, StreamSettings: `{"network":"tcp","security":"none"}`}
	if err := validateProtocolSettings(legacy); err != nil {
		t.Fatalf("legacy provisioning rejected before runtime installation: %v", err)
	}
}

func TestEmptyClientMutationsReturnErrors(t *testing.T) {
	service := protocolDB(t)
	data := &model.Inbound{Settings: `{"clients":[]}`}
	if _, err := service.AddInboundClient(data); err == nil {
		t.Fatal("empty client addition accepted")
	}
	if _, err := service.UpdateInboundClient(data, "missing"); err == nil {
		t.Fatal("empty client update accepted")
	}
}
