package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/xray"

	"go.uber.org/atomic"
)

var (
	p                 *xray.Process
	processMu         sync.RWMutex
	lock              sync.Mutex
	isNeedXrayRestart atomic.Bool
)

func currentXrayProcess() *xray.Process {
	processMu.RLock()
	defer processMu.RUnlock()
	return p
}

type XrayService struct {
	inboundService InboundService
	settingService SettingService
	xrayAPI        xray.XrayAPI
}

func (s *XrayService) IsXrayRunning() bool {
	p := currentXrayProcess()
	return p != nil && p.IsRunning()
}

func (s *XrayService) GetXrayErr() error {
	p := currentXrayProcess()
	if p == nil {
		return nil
	}
	return p.GetErr()
}

func (s *XrayService) GetXrayResult() string {
	p := currentXrayProcess()
	if p == nil || p.IsRunning() {
		return ""
	}
	return p.GetResult()
}

func (s *XrayService) GetXrayVersion() string {
	p := currentXrayProcess()
	if p == nil {
		return "Unknown"
	}
	return p.GetVersion()
}

func RemoveIndex(s []interface{}, index int) []interface{} {
	return append(s[:index], s[index+1:]...)
}

func (s *XrayService) GetXrayConfig() (*xray.Config, error) {
	templateConfig, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}

	xrayConfig := &xray.Config{}
	err = json.Unmarshal([]byte(templateConfig), xrayConfig)
	if err != nil {
		return nil, err
	}

	s.inboundService.AddTraffic(nil, nil)

	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		// Sidecar protocols are managed outside Xray. Their settings stay in
		// SQLite so the legacy panel can preserve them without emitting an
		// invalid Xray inbound.
		if inbound.Protocol == model.MTProto || inbound.Protocol == model.TUIC || inbound.Protocol == model.AmneziaWG {
			continue
		}
		if err := xray.CheckLegacyStreamSettings(inbound.StreamSettings); err != nil {
			return nil, fmt.Errorf("inbound %s: %w", inbound.Tag, err)
		}
		// get settings clients
		settings := map[string]interface{}{}
		json.Unmarshal([]byte(inbound.Settings), &settings)
		clients, ok := settings["clients"].([]interface{})
		if ok {
			// check users active or not
			clientStats := inbound.ClientStats
			for _, clientTraffic := range clientStats {
				indexDecrease := 0
				for index, client := range clients {
					c := client.(map[string]interface{})
					if c["email"] == clientTraffic.Email {
						if !clientTraffic.Enable {
							clients = RemoveIndex(clients, index-indexDecrease)
							indexDecrease++
							logger.Infof("Remove Inbound User %s due to expiration or traffic limit", c["email"])
						}
					}
				}
			}

			// clear client config for additional parameters
			var final_clients []interface{}
			for _, client := range clients {
				c := client.(map[string]interface{})
				if c["enable"] != nil {
					if enable, ok := c["enable"].(bool); ok && !enable {
						continue
					}
				}
				// GenXrayInboundConfig strips panel metadata and normalizes
				// credentials centrally. An old allowlist here erased newer
				// protocol fields such as Hysteria auth and MASQUE pass.
				final_clients = append(final_clients, interface{}(c))
			}

			settings["clients"] = final_clients
			modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return nil, err
			}

			inbound.Settings = string(modifiedSettings)
		}

		if len(inbound.StreamSettings) > 0 {
			// Unmarshal stream JSON
			var stream map[string]interface{}
			json.Unmarshal([]byte(inbound.StreamSettings), &stream)

			// Remove the "settings" field under "tlsSettings" and "realitySettings"
			tlsSettings, ok1 := stream["tlsSettings"].(map[string]interface{})
			realitySettings, ok2 := stream["realitySettings"].(map[string]interface{})
			if ok1 || ok2 {
				if ok1 {
					delete(tlsSettings, "settings")
				} else if ok2 {
					delete(realitySettings, "settings")
				}
			}

			delete(stream, "externalProxy")

			newStream, err := json.MarshalIndent(stream, "", "  ")
			if err != nil {
				return nil, err
			}
			inbound.StreamSettings = string(newStream)
		}

		inboundConfig := inbound.GenXrayInboundConfig()
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *inboundConfig)
	}
	xray.NormalizeConfigProtocols(xrayConfig)
	return xrayConfig, nil
}

func (s *XrayService) GetXrayTraffic() ([]*xray.Traffic, []*xray.ClientTraffic, error) {
	p := currentXrayProcess()
	if p == nil || !p.IsRunning() {
		err := errors.New("xray is not running")
		logger.Debug("Attempted to fetch Xray traffic, but Xray is not running:", err)
		return nil, nil, err
	}
	apiPort := p.GetAPIPort()
	s.xrayAPI.Init(apiPort)
	defer s.xrayAPI.Close()

	traffic, clientTraffic, err := s.xrayAPI.GetTraffic(true)
	if err != nil {
		logger.Debug("Failed to fetch Xray traffic:", err)
		return nil, nil, err
	}
	return traffic, clientTraffic, nil
}

func (s *XrayService) RestartXray(isForce bool) error {
	lock.Lock()
	defer lock.Unlock()
	return s.restartXrayLocked(isForce)
}

func (s *XrayService) restartXrayLocked(isForce bool) error {
	logger.Debug("restart xray, force:", isForce)

	xrayConfig, err := s.GetXrayConfig()
	if err != nil {
		return err
	}

	previous := currentXrayProcess()
	wasRunning := previous != nil && previous.IsRunning()
	if wasRunning {
		if !isForce && previous.GetConfig().Equals(xrayConfig) {
			logger.Debug("It does not need to restart xray")
			return nil
		}
	}
	// Validate the complete effective template with the installed core before
	// stopping a working process. A bad advanced-protocol setting must not
	// disconnect every otherwise healthy inbound.
	if err := xray.ValidateConfig(xrayConfig); err != nil {
		return err
	}
	if wasRunning {
		if err := previous.Stop(); err != nil {
			return err
		}
	}

	next := xray.NewProcess(xrayConfig)
	processMu.Lock()
	p = next
	processMu.Unlock()
	err = next.Start()
	if err != nil {
		// Startup failures must not strand a previously working configuration.
		if wasRunning {
			if rollbackErr := previous.Start(); rollbackErr != nil {
				return errors.Join(err, fmt.Errorf("restore previous Xray: %w", rollbackErr))
			}
			processMu.Lock()
			p = previous
			processMu.Unlock()
		}
		return err
	}
	return nil
}

func (s *XrayService) StopXray() error {
	lock.Lock()
	defer lock.Unlock()
	logger.Debug("Attempting to stop Xray...")
	p := currentXrayProcess()
	if p != nil && p.IsRunning() {
		return p.Stop()
	}
	return errors.New("xray is not running")
}

func (s *XrayService) SetToNeedRestart() {
	isNeedXrayRestart.Store(true)
}

func (s *XrayService) IsNeedRestartAndSetFalse() bool {
	return isNeedXrayRestart.CompareAndSwap(true, false)
}
