package tuic

import (
	"strings"
	"testing"

	"x-ui/database/model"
)

func TestParseInstanceAddsDefaultServer(t *testing.T) {
	inst, ok := parseInstance(&model.Inbound{
		Id:       7,
		Port:     443,
		Protocol: Protocol,
		Enable:   true,
		Settings: `{"users":{"00000000-0000-0000-0000-000000000000":"password"}}`,
	})
	if !ok {
		t.Fatal("expected valid TUIC instance")
	}
	if !strings.Contains(string(inst.config), `"server": "0.0.0.0:443"`) {
		t.Fatalf("default server missing from config: %s", inst.config)
	}
}
