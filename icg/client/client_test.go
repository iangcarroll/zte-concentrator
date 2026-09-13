package client

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/iangcarroll/zte-concentrator/icg"
)

func TestCountFlowDataCountsUniquePayloadAcrossLegs(t *testing.T) {
	c := New(Config{})
	flow := icg.Flow{
		Client: netip.MustParseAddrPort("192.0.2.10:1234"),
		Server: netip.MustParseAddrPort("198.51.100.20:80"),
	}
	other := icg.Flow{
		Client: netip.MustParseAddrPort("192.0.2.11:1234"),
		Server: flow.Server,
	}

	c.Frames <- receivedPayload(other, 1, "ignored")
	c.Frames <- receivedPayload(flow, 11, "abc")
	c.Frames <- receivedPayload(flow, 11, "abc") // retransmit
	c.Frames <- receivedPayload(flow, 10, "de")  // arrives out of order

	got, err := c.CountFlowData(flow, time.Second, 5)
	if err != nil {
		t.Fatalf("CountFlowData: %v", err)
	}
	if got != 5 {
		t.Fatalf("count = %d, want 5", got)
	}
}

func TestCountFlowDataReportsShortClosedFlow(t *testing.T) {
	c := New(Config{})
	flow := icg.Flow{
		Client: netip.MustParseAddrPort("192.0.2.10:1234"),
		Server: netip.MustParseAddrPort("198.51.100.20:80"),
	}
	c.Frames <- receivedPayload(flow, 1, "short")
	c.Frames <- receivedTCP(flow, 2, icg.TCPDisconnect, nil)

	got, err := c.CountFlowData(flow, 10*time.Millisecond, 100)
	if got != 5 {
		t.Fatalf("count = %d, want 5", got)
	}
	if err == nil || !strings.Contains(err.Error(), "flow closed after 5 bytes") {
		t.Fatalf("error = %v, want closed-flow detail", err)
	}
}

func receivedPayload(flow icg.Flow, seq uint32, data string) Received {
	return receivedTCP(flow, seq, icg.TCPPayload, []byte(data))
}

func receivedTCP(flow icg.Flow, seq uint32, opcode icg.TCPOpcode, data []byte) Received {
	body := icg.TCPBody{
		Seq:    seq,
		Opcode: opcode,
		Src:    flow.Server,
		Dst:    flow.Client,
		Data:   data,
	}
	return Received{Frame: &icg.Frame{Type: icg.TypeTCPDown, Body: body.AppendTo(nil)}}
}
