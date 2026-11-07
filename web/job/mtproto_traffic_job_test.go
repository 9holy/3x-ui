package job

import (
	"testing"

	"x-ui/xray"
)

func TestMTProtoTrafficIncludesInboundTotalsAndMergesRetriedIntervals(t *testing.T) {
	inbounds, clients := aggregateMtprotoTraffic([]*xray.ClientTraffic{
		{InboundId: 1, Email: "first", Up: 10, Down: 20},
		{InboundId: 1, Email: "first", Up: 5, Down: 6},
		{InboundId: 1, Email: "second", Up: 1, Down: 2},
		{InboundId: 99, Email: "deleted", Up: 1000, Down: 1000},
	}, map[int]string{1: "inbound-12345"})
	if len(inbounds) != 1 || inbounds[0].Up != 16 || inbounds[0].Down != 28 || !inbounds[0].IsInbound {
		t.Fatalf("wrong inbound totals: %+v", inbounds)
	}
	if len(clients) != 2 {
		t.Fatalf("unexpected client count: %d", len(clients))
	}
	for _, client := range clients {
		if client.Email == "first" && (client.Up != 15 || client.Down != 26) {
			t.Fatal("retried interval would be dropped by the SQLite updater")
		}
	}
}
