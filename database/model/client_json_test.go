package model

import (
	"encoding/json"
	"testing"
)

func TestClientAcceptsLegacyTelegramIDs(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      int64
	}{
		{"empty", `""`, 0},
		{"whitespace", `"  "`, 0},
		{"number", `12345`, 12345},
		{"string", `"12345"`, 12345},
		{"legacy-spaces", `"12 345"`, 12345},
		{"group", `"-1001234567890"`, -1001234567890},
		{"null", `null`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var client Client
			if err := json.Unmarshal([]byte(`{"id":"kept-id","email":"kept-email","enable":true,"totalGB":2147483648,"expiryTime":-259200000,"tgId":`+tc.raw+`}`), &client); err != nil {
				t.Fatal(err)
			}
			if client.TgID != tc.want || client.ID != "kept-id" || client.Email != "kept-email" || !client.Enable || client.TotalGB != 2147483648 || client.ExpiryTime != -259200000 {
				t.Fatalf("client fields changed: %+v", client)
			}
			encoded, err := json.Marshal(client)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			var id int64
			if err := json.Unmarshal(fields["tgId"], &id); err != nil || id != tc.want {
				t.Fatalf("canonical Telegram ID is not a number: %s", encoded)
			}
		})
	}
}

func TestClientStillRejectsInvalidJSONFieldTypes(t *testing.T) {
	for _, raw := range []string{
		`{"tgId":"not-a-number"}`, `{"tgId":"1.5"}`, `{"tgId":"9223372036854775808"}`,
		`{"tgId":1.5}`, `{"tgId":true}`, `{"tgId":[]}`, `{"tgId":{}}`,
		`{"tgId":"","totalGB":"invalid"}`, `{"tgId":"","enable":"true"}`,
	} {
		var client Client
		if err := json.Unmarshal([]byte(raw), &client); err == nil {
			t.Errorf("invalid client accepted: %s", raw)
		}
	}
}
