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
		wanted := make([]tuic.Inbound, 0, len(inbounds))
		for _, inbound := range inbounds {
			wanted = append(wanted, tuic.Inbound{
				Id: inbound.Id, Listen: inbound.Listen, Port: inbound.Port,
				Protocol: string(inbound.Protocol), Enable: inbound.Enable,
				Settings: inbound.Settings,
			})
		}
		tuic.GetManager().Reconcile(wanted)
	}
}
