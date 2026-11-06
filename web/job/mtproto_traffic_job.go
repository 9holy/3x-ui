package job

import (
	"x-ui/mtproto"
	"x-ui/web/service"
)

type MtprotoTrafficJob struct {
	inboundService service.InboundService
}

func NewMtprotoTrafficJob() *MtprotoTrafficJob { return &MtprotoTrafficJob{} }

func (j *MtprotoTrafficJob) Run() {
	traffic := mtproto.GetManager().CollectTraffic()
	if len(traffic) == 0 {
		return
	}
	_, _ = j.inboundService.AddTraffic(nil, traffic)
}
