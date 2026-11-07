package job

import (
	"sync"

	"x-ui/logger"
	"x-ui/mtproto"
	"x-ui/web/service"
	"x-ui/xray"
)

type MtprotoTrafficJob struct {
	mu             sync.Mutex
	inboundService service.InboundService
	xrayService    service.XrayService
}

func NewMtprotoTrafficJob() *MtprotoTrafficJob { return &MtprotoTrafficJob{} }

func (j *MtprotoTrafficJob) Run() {
	j.mu.Lock()
	defer j.mu.Unlock()
	inbounds, err := j.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("mtproto traffic: read inbounds failed:", err)
		return
	}
	tags := make(map[int]string, len(inbounds))
	for _, inbound := range inbounds {
		tags[inbound.Id] = inbound.Tag
	}
	mgr := mtproto.GetManager()
	traffic := mgr.CollectTraffic()
	inboundTraffic, clientTraffic := aggregateMtprotoTraffic(traffic, tags)
	err, restart := j.inboundService.AddTraffic(inboundTraffic, clientTraffic)
	if err != nil {
		mgr.RetryTraffic(traffic)
		logger.Warning("mtproto traffic: save failed:", err)
	}
	if restart {
		j.xrayService.SetToNeedRestart()
	}
}

func aggregateMtprotoTraffic(traffic []*xray.ClientTraffic, tags map[int]string) ([]*xray.Traffic, []*xray.ClientTraffic) {
	inbounds := make(map[string]*xray.Traffic)
	clients := make(map[string]*xray.ClientTraffic)
	for _, delta := range traffic {
		tag, exists := tags[delta.InboundId]
		if !exists {
			continue
		}
		if inbounds[tag] == nil {
			inbounds[tag] = &xray.Traffic{Tag: tag, IsInbound: true}
		}
		inbounds[tag].Up += delta.Up
		inbounds[tag].Down += delta.Down
		if clients[delta.Email] == nil {
			clients[delta.Email] = &xray.ClientTraffic{InboundId: delta.InboundId, Email: delta.Email}
		}
		clients[delta.Email].Up += delta.Up
		clients[delta.Email].Down += delta.Down
	}
	inboundTraffic := make([]*xray.Traffic, 0, len(inbounds))
	for _, traffic := range inbounds {
		inboundTraffic = append(inboundTraffic, traffic)
	}
	clientTraffic := make([]*xray.ClientTraffic, 0, len(clients))
	for _, traffic := range clients {
		clientTraffic = append(clientTraffic, traffic)
	}
	return inboundTraffic, clientTraffic
}
