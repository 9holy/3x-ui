package job

import (
	"x-ui/amneziawg"
	"x-ui/web/service"
)

type AmneziaWGJob struct {
	inboundService service.InboundService
}

func NewAmneziaWGJob() *AmneziaWGJob { return &AmneziaWGJob{} }

func (j *AmneziaWGJob) Run() {
	inbounds, err := j.inboundService.GetAllInbounds()
	if err != nil {
		return
	}
	amneziawg.GetManager().Reconcile(inbounds)
}
