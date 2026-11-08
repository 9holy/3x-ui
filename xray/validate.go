package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ValidateInboundConfig rejects invalid native protocol settings before they
// are saved and can take down the shared core at its next full restart.
func ValidateInboundConfig(inbound []byte) error {
	if !json.Valid(inbound) {
		return fmt.Errorf("invalid inbound JSON")
	}
	config := append([]byte(`{"inbounds":[`), inbound...)
	config = append(config, []byte(`],"outbounds":[{"protocol":"freedom"}]}`)...)
	return validateNativeConfig(config)
}

func ValidateConfig(config *Config) error {
	return ValidateConfigWithBinary(config, GetBinaryPath())
}

func ValidateConfigWithBinary(config *Config, binary string) error {
	encoded, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return validateNativeConfigBinary(encoded, binary)
}

func validateNativeConfig(config []byte) error {
	return validateNativeConfigBinary(config, GetBinaryPath())
}

func validateNativeConfigBinary(config []byte, binary string) error {
	f, err := os.CreateTemp("", "xui-validate-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(config); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "run", "-test", "-c", f.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Xray rejected the configuration: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
