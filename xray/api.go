package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"x-ui/logger"
	"x-ui/util/common"

	"github.com/xtls/xray-core/app/proxyman/command"
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type XrayAPI struct {
	HandlerServiceClient *command.HandlerServiceClient
	StatsServiceClient   *statsService.StatsServiceClient
	grpcClient           *grpc.ClientConn
	isConnected          bool
	apiPort              int
}

func (x *XrayAPI) Init(apiPort int) error {
	if apiPort <= 0 {
		return fmt.Errorf("invalid Xray API port: %d", apiPort)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to Xray API: %w", err)
	}

	x.grpcClient = conn
	x.isConnected = true
	x.apiPort = apiPort

	hsClient := command.NewHandlerServiceClient(conn)
	ssClient := statsService.NewStatsServiceClient(conn)

	x.HandlerServiceClient = &hsClient
	x.StatsServiceClient = &ssClient

	return nil
}

func (x *XrayAPI) Close() {
	if x.grpcClient != nil {
		x.grpcClient.Close()
	}
	x.HandlerServiceClient = nil
	x.StatsServiceClient = nil
	x.isConnected = false
}

func (x *XrayAPI) AddInbound(inbound []byte) error {
	if !x.isConnected || x.apiPort <= 0 {
		return common.NewError("xray api is not initialized")
	}
	if !json.Valid(inbound) {
		return common.NewError("invalid inbound JSON")
	}
	// Use the installed core's parser. The panel's legacy protobuf dependency
	// cannot build newer protocols and silently drops unknown transport fields.
	// A failed native API update falls back to the service's full-config restart.
	f, err := os.CreateTemp("", "xui-inbound-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	config := append([]byte(`{"inbounds":[`), inbound...)
	config = append(config, []byte(`]}`)...)
	if _, err = f.Write(config); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, GetBinaryPath(), "api", "adi",
		fmt.Sprintf("--server=127.0.0.1:%d", x.apiPort), "--timeout=5", f.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("native Xray inbound update failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (x *XrayAPI) DelInbound(tag string) error {
	client := *x.HandlerServiceClient
	_, err := client.RemoveInbound(context.Background(), &command.RemoveInboundRequest{
		Tag: tag,
	})
	return err
}

func (x *XrayAPI) AddUser(Protocol string, inboundTag string, user map[string]interface{}) error {
	var account *serial.TypedMessage
	switch Protocol {
	case "vmess":
		account = serial.ToTypedMessage(&vmess.Account{
			Id: user["id"].(string),
		})
	case "vless":
		account = serial.ToTypedMessage(&vless.Account{
			Id:   user["id"].(string),
			Flow: user["flow"].(string),
		})
	case "trojan":
		account = serial.ToTypedMessage(&trojan.Account{
			Password: user["password"].(string),
		})
	case "shadowsocks":
		var ssCipherType shadowsocks.CipherType
		switch user["cipher"].(string) {
		case "aes-128-gcm":
			ssCipherType = shadowsocks.CipherType_AES_128_GCM
		case "aes-256-gcm":
			ssCipherType = shadowsocks.CipherType_AES_256_GCM
		case "chacha20-poly1305", "chacha20-ietf-poly1305":
			ssCipherType = shadowsocks.CipherType_CHACHA20_POLY1305
		case "xchacha20-poly1305", "xchacha20-ietf-poly1305":
			ssCipherType = shadowsocks.CipherType_XCHACHA20_POLY1305
		default:
			ssCipherType = shadowsocks.CipherType_NONE
		}

		if ssCipherType != shadowsocks.CipherType_NONE {
			account = serial.ToTypedMessage(&shadowsocks.Account{
				Password:   user["password"].(string),
				CipherType: ssCipherType,
			})
		} else {
			account = serial.ToTypedMessage(&shadowsocks_2022.User{
				Key:   user["password"].(string),
				Email: user["email"].(string),
			})
		}
	default:
		return fmt.Errorf("protocol %s requires a full Xray config update", Protocol)
	}

	client := *x.HandlerServiceClient

	_, err := client.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Email:   user["email"].(string),
				Account: account,
			},
		}),
	})
	return err
}

func (x *XrayAPI) RemoveUser(inboundTag, email string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	op := &command.RemoveUserOperation{Email: email}
	req := &command.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: serial.ToTypedMessage(op),
	}

	_, err := (*x.HandlerServiceClient).AlterInbound(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to remove user: %w", err)
	}

	return nil
}

func (x *XrayAPI) GetTraffic(reset bool) ([]*Traffic, []*ClientTraffic, error) {
	if x.grpcClient == nil {
		return nil, nil, common.NewError("xray api is not initialized")
	}

	trafficRegex := regexp.MustCompile(`(inbound|outbound)>>>([^>]+)>>>traffic>>>(downlink|uplink)`)
	clientTrafficRegex := regexp.MustCompile(`user>>>([^>]+)>>>traffic>>>(downlink|uplink)`)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if x.StatsServiceClient == nil {
		return nil, nil, common.NewError("xray StatusServiceClient is not initialized")
	}

	resp, err := (*x.StatsServiceClient).QueryStats(ctx, &statsService.QueryStatsRequest{Reset_: reset})
	if err != nil {
		logger.Debug("Failed to query Xray stats:", err)
		return nil, nil, err
	}

	tagTrafficMap := make(map[string]*Traffic)
	emailTrafficMap := make(map[string]*ClientTraffic)

	for _, stat := range resp.GetStat() {
		if matches := trafficRegex.FindStringSubmatch(stat.Name); len(matches) == 4 {
			processTraffic(matches, stat.Value, tagTrafficMap)
		} else if matches := clientTrafficRegex.FindStringSubmatch(stat.Name); len(matches) == 3 {
			processClientTraffic(matches, stat.Value, emailTrafficMap)
		}
	}
	return mapToSlice(tagTrafficMap), mapToSlice(emailTrafficMap), nil
}

func processTraffic(matches []string, value int64, trafficMap map[string]*Traffic) {
	isInbound := matches[1] == "inbound"
	tag := matches[2]
	isDown := matches[3] == "downlink"

	if tag == "api" {
		return
	}

	traffic, ok := trafficMap[tag]
	if !ok {
		traffic = &Traffic{
			IsInbound:  isInbound,
			IsOutbound: !isInbound,
			Tag:        tag,
		}
		trafficMap[tag] = traffic
	}

	if isDown {
		traffic.Down = value
	} else {
		traffic.Up = value
	}
}

func processClientTraffic(matches []string, value int64, clientTrafficMap map[string]*ClientTraffic) {
	email := matches[1]
	isDown := matches[2] == "downlink"

	traffic, ok := clientTrafficMap[email]
	if !ok {
		traffic = &ClientTraffic{Email: email}
		clientTrafficMap[email] = traffic
	}

	if isDown {
		traffic.Down = value
	} else {
		traffic.Up = value
	}
}

func mapToSlice[T any](m map[string]*T) []*T {
	result := make([]*T, 0, len(m))
	for _, v := range m {
		result = append(result, v)
	}
	return result
}
