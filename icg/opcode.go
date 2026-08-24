package icg

import "fmt"

// Type is the packet class, at body offset 4. Recovered from the client's
// receive dispatcher handle_recv_packet (0x24b4c). See ICG_WIRE_PROTOCOL.md §3.
//
// Note the asymmetry on TCP data: the client sends TypeTCPUp and expects
// TypeTCPDown, so a concentrator must accept 6 and emit 2. UDP and ICMP use the
// same number in both directions.
type Type uint8

const (
	TypeUDP       Type = 0 // tunnelled UDP: payload is a raw IPv4 packet, sequenced
	TypeICMP      Type = 1 // tunnelled ICMP: payload is a raw IPv4 packet, unsequenced
	TypeTCPDown   Type = 2 // TCP data, server -> client
	TypeHandshake Type = 3 // handshake, keepalive, UDP-leg RTT sync
	TypeAck       Type = 4 // ACKs, retransmit requests, telemetry
	TypeTCPUp     Type = 6 // TCP data, client -> server
	TypeSeqSync   Type = 7 // global sequence resynchronisation
)

func (t Type) String() string {
	switch t {
	case TypeUDP:
		return "UDP"
	case TypeICMP:
		return "ICMP"
	case TypeTCPDown:
		return "TCP_DOWN"
	case TypeHandshake:
		return "HANDSHAKE"
	case TypeAck:
		return "ACK"
	case TypeTCPUp:
		return "TCP_UP"
	case TypeSeqSync:
		return "SEQ_SYNC"
	default:
		return fmt.Sprintf("TYPE_%d", uint8(t))
	}
}

// Handshake opcodes (Type == TypeHandshake). The numbering comes from the
// const char* table the binary carries at file offset 0x500a0, which
// handle_recv_handshake_packet indexes by opcode. §4.
const (
	HSKeepalive     uint8 = 0 // client -> server, payload is a fake ICMP ping
	HSReqWithConfig uint8 = 1 // client -> server, 50-byte device/config struct
	HSConfirmAck    uint8 = 2 // client -> server, payload is a fake ICMP ping
	HSServerAck     uint8 = 3 // server -> client, payload IGNORED by the client
	HSReserved      uint8 = 4 // "HANDSHAKE_CODE_RESREVER" (sic), unused
	HSRTTSync       uint8 = 5 // client -> server, on a UDP leg
	HSRTTSyncAck    uint8 = 6 // server -> client, on a UDP leg
	HSRTTAck        uint8 = 7 // client -> server, echoes the SyncAck verbatim
)

// Ack-family opcodes (Type == TypeAck). From handle_server_ack_packet
// (0x1a1a4) and handle_misc_packet (0x11920). §5.
const (
	AckUDPRetranRange uint8 = 2  // seq list, SeqList layout
	AckTCPRetranRange uint8 = 3  // seq list, SeqList layout
	AckTCPRetranOne   uint8 = 4  // empty; seq in the sub-header
	AckTCPCumulative  uint8 = 5  // empty; cumulative seq in the sub-header
	AckUDPRetranOne   uint8 = 8  // empty; seq in the sub-header
	AckUDPCumulative  uint8 = 9  // empty; cumulative seq in the sub-header
	AckReportConfig   uint8 = 11 // client telemetry: server config
	AckReportPriority uint8 = 12 // client telemetry: card priority table
	AckReportStatus   uint8 = 13 // client telemetry: card status table
	AckReportSpeed    uint8 = 14 // client telemetry: speed-limit table
	AckTunnelDetect   uint8 = 15 // server -> client liveness probe
)

// Sequence-resync opcodes (Type == TypeSeqSync). From handle_sort_sync_packet
// (0x13c5c). §9.
const (
	SyncTCPRequest uint8 = 6  // peer asks us to declare our TCP position
	SyncTCPAck     uint8 = 7  // accepted and discarded by the client
	SyncUDPRequest uint8 = 10 // peer asks us to declare our UDP position
	SyncUDPAck     uint8 = 11 // accepted and discarded by the client
)

// TCPOpcode is the per-flow opcode inside a TCP data body, at payload offset 4
// (little-endian u16). Distinct from Frame.Opcode, which is 0 for all TCP data
// frames. §7.
type TCPOpcode uint16

const (
	TCPConnect    TCPOpcode = 0 // open the upstream socket; body carries no data
	TCPDisconnect TCPOpcode = 1 // peer closed; body carries no data
	TCPPayload    TCPOpcode = 3 // stream data follows the 18-byte header
	// TCPBlock/TCPUnblock are INFERRED: proxy_fd_monitor_proc stores 4 and 5
	// into the per-fd state it later uses as the opcode. Flow control; we
	// never send them and only log them inbound.
	TCPBlock   TCPOpcode = 4
	TCPUnblock TCPOpcode = 5
)

func (o TCPOpcode) String() string {
	switch o {
	case TCPConnect:
		return "CONNECT"
	case TCPDisconnect:
		return "DISCONNECT"
	case TCPPayload:
		return "PAYLOAD"
	case TCPBlock:
		return "BLOCK"
	case TCPUnblock:
		return "UNBLOCK"
	default:
		return fmt.Sprintf("TCPOPT_%d", uint16(o))
	}
}

// OpcodeName renders an opcode in the context of its type, using ZTE's own
// names where the binary gave us one.
func OpcodeName(t Type, op uint8) string {
	var m map[uint8]string
	switch t {
	case TypeHandshake:
		m = handshakeNames
	case TypeAck:
		m = ackNames
	case TypeSeqSync:
		m = syncNames
	default:
		if op == 0 {
			return "0"
		}
		return fmt.Sprintf("%d", op)
	}
	if n, ok := m[op]; ok {
		return n
	}
	return fmt.Sprintf("op%d?", op)
}

// Names as they appear verbatim in zte_icg_agg's string tables, so that log
// output can be grepped against the device's own /logfs/zte_icg_agg_log.
var handshakeNames = map[uint8]string{
	HSKeepalive:     "ICG_KEEPALIVE",
	HSReqWithConfig: "ICG_HANDSHAKE_REQ_WITH_CONFIG",
	HSConfirmAck:    "ICG_CONFIRM_SERVER_ACK",
	HSServerAck:     "ICG_SERVER_HANDSHAKE_ACK",
	HSReserved:      "HANDSHAKE_CODE_RESREVER",
	HSRTTSync:       "ICG_UDP_CHNN_RTT_SYNC",
	HSRTTSyncAck:    "ICG_UDP_CHNN_RTT_SYNC_ACK",
	HSRTTAck:        "ICG_UDP_CHNN_RTT_ACK",
}

var ackNames = map[uint8]string{
	AckUDPRetranRange: "UDP_REQUEST_TRANS_RANGE",
	AckTCPRetranRange: "TCP_REQUEST_TRANS_RANGE",
	AckTCPRetranOne:   "TCP_REQUEST_TRANS",
	AckTCPCumulative:  "TCP_ACCUMU_ACK",
	AckUDPRetranOne:   "UDP_REQUEST_TRANS",
	AckUDPCumulative:  "UDP_ACCUMU_ACK",
	AckReportConfig:   "REPORT_SERVER_CONFIG",
	AckReportPriority: "REPORT_CARD_PRIORITY",
	AckReportStatus:   "REPORT_CARD_STATUS",
	AckReportSpeed:    "REPORT_CARD_SPEED",
	AckTunnelDetect:   "TUNNEL_DETECT",
}

var syncNames = map[uint8]string{
	SyncTCPRequest: "TCP_SORT_SYNC_REQ",
	SyncTCPAck:     "TCP_SORT_SYNC_ACK",
	SyncUDPRequest: "UDP_SORT_SYNC_REQ",
	SyncUDPAck:     "UDP_SORT_SYNC_ACK",
}

// State is the client's handshake state, from the name table at 0x50088. The
// concentrator tracks its own view of it per session. §6.
type State uint8

const (
	StateInit     State = 0 // ICG_INIT_STATE
	StateSrvReady State = 1 // ICG_SERVER_READY   — client got our HSServerAck
	StateBothOK   State = 2 // ICG_AND_SRV_BOTH_OK — client sent HSConfirmAck
)

func (s State) String() string {
	switch s {
	case StateInit:
		return "ICG_INIT_STATE"
	case StateSrvReady:
		return "ICG_SERVER_READY"
	case StateBothOK:
		return "ICG_AND_SRV_BOTH_OK"
	default:
		return fmt.Sprintf("STATE_%d", uint8(s))
	}
}
