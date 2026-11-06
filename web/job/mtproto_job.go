package job

import (
	"x-ui/mtproto"
	"x-ui/web/service"
)

type MtprotoJob struct {
	inboundService service.InboundService
}

func NewMtprotoJob() *MtprotoJob { return &MtprotoJob{} }

func (j *MtprotoJob) Run() {
	inbounds, err := j.inboundService.GetAllInbounds()
	if err != nil {
		return
	}
	mtproto.GetManager().Reconcile(inbounds)
}
