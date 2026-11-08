package service

import "fmt"

// ValidateStoredProtocols is used by the installer's isolated database copy.
// It checks runtime availability and effective settings without starting a
// sidecar, opening a listener, or changing the production database.
func (s *InboundService) ValidateStoredProtocols() error {
	inbounds, err := s.GetAllInbounds()
	if err != nil {
		return err
	}
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		if err := validateProtocolSettings(inbound); err != nil {
			return fmt.Errorf("inbound %s (%s): %w", inbound.Tag, inbound.Protocol, err)
		}
	}
	return nil
}
