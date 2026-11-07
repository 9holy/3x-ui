package job

import (
	"x-ui/tuic"
	"x-ui/web/service"
)

type TuicJob struct{ inboundService service.InboundService }

func NewTuicJob() *TuicJob { return &TuicJob{} }
func (j *TuicJob) Run() {
	inbounds, err := j.inboundService.GetAllInbounds()
	if err == nil {
		tuic.GetManager().Reconcile(inbounds)
	}
}
