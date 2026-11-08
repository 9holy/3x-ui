package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// UnmarshalJSON accepts Telegram IDs emitted by the original panel, which used
// an empty string for an unset ID and could store a numeric ID as a string.
// All other client fields retain their normal JSON type validation.
func (c *Client) UnmarshalJSON(data []byte) error {
	type plainClient Client
	var value plainClient
	wire := struct {
		*plainClient
		TelegramID json.RawMessage `json:"tgId"`
	}{plainClient: &value}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if len(wire.TelegramID) > 0 && string(wire.TelegramID) != "null" {
		if wire.TelegramID[0] == '"' {
			var text string
			if err := json.Unmarshal(wire.TelegramID, &text); err != nil {
				return err
			}
			text = strings.ReplaceAll(strings.TrimSpace(text), " ", "")
			if text != "" {
				id, err := strconv.ParseInt(text, 10, 64)
				if err != nil {
					return fmt.Errorf("client tgId must be an integer: %w", err)
				}
				value.TgID = id
			}
		} else if err := json.Unmarshal(wire.TelegramID, &value.TgID); err != nil {
			return fmt.Errorf("client tgId must be an integer: %w", err)
		}
	}
	*c = Client(value)
	return nil
}
