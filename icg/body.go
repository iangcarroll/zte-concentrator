package icg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

var ErrBodyShort = errors.New("icg: body too short")

// ---------------------------------------------------------------------------
// TCP data (Type 6 up / Type 2 down) — ICG_WIRE_PROTOCOL.md §7
// ---------------------------------------------------------------------------

// TCPHdrLen is the fixed part of a TCP data body.
const TCPHdrLen = 18

// TCPBody is a TCP data frame's payload: a global sequence number, a per-flow
// opcode, the ORIGINAL LAN client's 5-tuple, and stream bytes.
//
// The tuple is stored sender-relative, so on the downlink Src/Dst are swapped
// relative to the uplink. The mixed endianness is ZTE's, not ours: Seq and
// Opcode are little-endian (host order on the device), the addresses and ports
// are network order.
//
//	 0 u32 LE  Seq
//	 4 u16 LE  Opcode
//	 6 u32 BE  source address
//	10 u32 BE  destination address
//	14 u16 BE  source port
//	16 u16 BE  destination port
//	18 ...    Data
type TCPBody struct {
	Seq    uint32
	Opcode TCPOpcode
	Src    netip.AddrPort
	Dst    netip.AddrPort
	Data   []byte
}

// ParseTCPBody decodes a TCP data payload. Data aliases b.
func ParseTCPBody(b []byte) (TCPBody, error) {
	var t TCPBody
	if len(b) < TCPHdrLen {
		return t, fmt.Errorf("%w: tcp body %d < %d", ErrBodyShort, len(b), TCPHdrLen)
	}
	t.Seq = binary.LittleEndian.Uint32(b[0:])
	t.Opcode = TCPOpcode(binary.LittleEndian.Uint16(b[4:]))
	t.Src = netip.AddrPortFrom(addr4(b[6:10]), binary.BigEndian.Uint16(b[14:]))
	t.Dst = netip.AddrPortFrom(addr4(b[10:14]), binary.BigEndian.Uint16(b[16:]))
	t.Data = b[TCPHdrLen:]
	return t, nil
}

// AppendTo encodes the body onto dst.
func (t TCPBody) AppendTo(dst []byte) []byte {
	var h [TCPHdrLen]byte
	binary.LittleEndian.PutUint32(h[0:], t.Seq)
	binary.LittleEndian.PutUint16(h[4:], uint16(t.Opcode))
	copy(h[6:10], as4(t.Src.Addr()))
	copy(h[10:14], as4(t.Dst.Addr()))
	binary.BigEndian.PutUint16(h[14:], t.Src.Port())
	binary.BigEndian.PutUint16(h[16:], t.Dst.Port())
	dst = append(dst, h[:]...)
	return append(dst, t.Data...)
}

// Flow is the 5-tuple key identifying one proxied TCP connection, oriented
// LAN-client-first regardless of which direction the frame travelled.
type Flow struct {
	Client netip.AddrPort // the original LAN client
	Server netip.AddrPort // the original destination
}

// UpFlow reads an uplink (Type 6) body as a Flow.
func (t TCPBody) UpFlow() Flow { return Flow{Client: t.Src, Server: t.Dst} }

// DownBody builds the matching downlink (Type 2) body for a flow, with the
// tuple swapped as the client expects.
func (f Flow) DownBody(seq uint32, op TCPOpcode, data []byte) TCPBody {
	return TCPBody{Seq: seq, Opcode: op, Src: f.Server, Dst: f.Client, Data: data}
}

func (f Flow) String() string { return f.Client.String() + "->" + f.Server.String() }

// ---------------------------------------------------------------------------
// Retransmit request (Type 4, opcodes 2 and 3) — §5.1
// ---------------------------------------------------------------------------

// SeqListLen is the fixed payload size of a *_REQUEST_TRANS_RANGE frame:
// a count plus room for exactly SeqListMax entries, zero-padded. The client's
// builder memcpy's all 204 bytes regardless of how many are used, and rejects
// nothing on length, so we match it byte for byte.
const (
	SeqListMax = 50
	SeqListLen = 4 + 4*SeqListMax // 204
)

// ParseSeqList decodes a *_REQUEST_TRANS_RANGE payload. Everything is
// big-endian. A short body is tolerated as long as it holds the declared
// count, since only ZTE's builder guarantees the 204-byte padding.
func ParseSeqList(b []byte) ([]uint32, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("%w: seq list %d < 4", ErrBodyShort, len(b))
	}
	n := int(binary.BigEndian.Uint32(b))
	if n > SeqListMax {
		return nil, fmt.Errorf("icg: seq list count %d > %d", n, SeqListMax)
	}
	if len(b) < 4+4*n {
		return nil, fmt.Errorf("%w: seq list needs %d bytes, have %d", ErrBodyShort, 4+4*n, len(b))
	}
	out := make([]uint32, n)
	for i := range out {
		out[i] = binary.BigEndian.Uint32(b[4+4*i:])
	}
	return out, nil
}

// AppendSeqList encodes up to SeqListMax sequence numbers, zero-padded to the
// full SeqListLen the client always sends. Extra entries are dropped; callers
// should chunk.
func AppendSeqList(dst []byte, seqs []uint32) []byte {
	if len(seqs) > SeqListMax {
		seqs = seqs[:SeqListMax]
	}
	var b [SeqListLen]byte
	binary.BigEndian.PutUint32(b[0:], uint32(len(seqs)))
	for i, s := range seqs {
		binary.BigEndian.PutUint32(b[4+4*i:], s)
	}
	return append(dst, b[:]...)
}

// ---------------------------------------------------------------------------
// UDP-leg RTT sync (Type 3, opcodes 5/6/7) — §4.3
// ---------------------------------------------------------------------------

// RTTBodyLen is the fixed size of an RTT sync payload.
const RTTBodyLen = 25

// RTTBody is the UDP-channel round-trip probe.
//
// The timestamps are milliseconds since the Unix epoch held in a 64-bit value
// split into two LITTLE-ENDIAN 32-bit words, HIGH word first. That is not a
// normal encoding; it is what update_chnn_rtt_and_response_ack reconstructs
// with `orr x25, lo, hi lsl 32`.
//
//	 0 u32 LE  Seq
//	 4 u32 LE  ClientMS >> 32
//	 8 u32 LE  ClientMS & 0xffffffff
//	12 u32 LE  ServerMS >> 32
//	16 u32 LE  ServerMS & 0xffffffff
//	20 [5]u8   Trailer — meaning unmapped; echo it back unchanged
type RTTBody struct {
	Seq      uint32
	ClientMS uint64
	ServerMS uint64
	Trailer  [5]byte
}

func ParseRTTBody(b []byte) (RTTBody, error) {
	var r RTTBody
	if len(b) < RTTBodyLen {
		return r, fmt.Errorf("%w: rtt body %d < %d", ErrBodyShort, len(b), RTTBodyLen)
	}
	r.Seq = binary.LittleEndian.Uint32(b[0:])
	r.ClientMS = splitMS(b[4:])
	r.ServerMS = splitMS(b[12:])
	copy(r.Trailer[:], b[20:25])
	return r, nil
}

func (r RTTBody) AppendTo(dst []byte) []byte {
	var b [RTTBodyLen]byte
	binary.LittleEndian.PutUint32(b[0:], r.Seq)
	putSplitMS(b[4:], r.ClientMS)
	putSplitMS(b[12:], r.ServerMS)
	copy(b[20:], r.Trailer[:])
	return append(dst, b[:]...)
}

// Reply builds the ICG_UDP_CHNN_RTT_SYNC_ACK the client needs: our own clock in
// ServerMS, and the client's timestamp echoed EXACTLY, because the client's RTT
// is computed as now-ClientMS against its own clock. Getting this wrong makes
// every leg look infinitely slow and the scheduler stops using it.
func (r RTTBody) Reply(now time.Time) RTTBody {
	r.ServerMS = uint64(now.UnixMilli())
	return r
}

func splitMS(b []byte) uint64 {
	hi := uint64(binary.LittleEndian.Uint32(b[0:]))
	lo := uint64(binary.LittleEndian.Uint32(b[4:]))
	return hi<<32 | lo
}

func putSplitMS(b []byte, v uint64) {
	binary.LittleEndian.PutUint32(b[0:], uint32(v>>32))
	binary.LittleEndian.PutUint32(b[4:], uint32(v))
}

// ---------------------------------------------------------------------------
// Handshake request (Type 3, opcode 1) — §4.1
// ---------------------------------------------------------------------------

// HandshakeReqLen is the payload size of ICG_HANDSHAKE_REQ_WITH_CONFIG.
const HandshakeReqLen = 50

// HandshakeReq is the client's opening message. The concentrator does not need
// any of it — the client never checks that we understood it (§6) — but the MAC
// is the device identity ZTE's cloud keys on, so it is worth logging.
//
// Fields beyond MAC/IcgID are device and config telemetry whose individual
// meanings are NOT mapped; Unknown holds them verbatim.
type HandshakeReq struct {
	MAC     net.HardwareAddr // payload 0..5
	IcgID   netip.Addr       // payload 6..9, inet_addr of the local tun IP
	Unknown [40]byte         // payload 10..49, all htonl'd u32s
}

func ParseHandshakeReq(b []byte) (HandshakeReq, error) {
	var h HandshakeReq
	if len(b) < HandshakeReqLen {
		return h, fmt.Errorf("%w: handshake req %d < %d", ErrBodyShort, len(b), HandshakeReqLen)
	}
	h.MAC = net.HardwareAddr(append([]byte(nil), b[0:6]...))
	h.IcgID = addr4(b[6:10])
	copy(h.Unknown[:], b[10:50])
	return h, nil
}

// ---------------------------------------------------------------------------
// The "fake ping" carried by keepalive and confirm frames — §4.2
// ---------------------------------------------------------------------------

// TunnelIDFromFakePing extracts the WAN leg index from the synthesised ICMP
// echo that ICG_KEEPALIVE and ICG_CONFIRM_SERVER_ACK carry. The ICMP data area
// starts with a TLV-looking {0x02, 0x04, id, 0, 0, 0}.
//
// INFERRED: the 0x02/0x04 prefix reads as type/length around a u32 tunnel id.
// Every observed id was < 16 and no TLV parser was located in the binary, so
// treat a mismatch as "unknown" rather than an error.
func TunnelIDFromFakePing(payload []byte) (id int, ok bool) {
	// 20-byte IPv4 header + 8-byte ICMP header, then the data area.
	const off = 20 + 8
	if len(payload) < off+6 || payload[0]>>4 != 4 {
		return 0, false
	}
	if payload[9] != 1 { // not ICMP
		return 0, false
	}
	if payload[off] != 0x02 || payload[off+1] != 0x04 {
		return 0, false
	}
	return int(binary.LittleEndian.Uint32(payload[off+2 : off+6])), true
}

// ---------------------------------------------------------------------------

func addr4(b []byte) netip.Addr {
	return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
}

func as4(a netip.Addr) []byte {
	b := a.As4()
	return b[:]
}
