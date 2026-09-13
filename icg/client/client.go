// Package client is a client-side implementation of the ICG bonding
// protocol — the half that zte_icg_agg speaks on a ZTE CPE.
//
// It exists to validate a concentrator without a device in the loop: it
// performs the real handshake, opens real WAN legs, and proxies real TCP flows
// through the tunnel, so an end-to-end fetch either works or does not. It is
// not a reimplementation of the device (no scheduling, no reorder buffer, no
// retransmission) and is not meant to be one.
//
// See docs/PROTOCOL.md; section numbers are cited below.
package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iangcarroll/zte-concentrator/icg"
)

// Config describes the concentrator to talk to and how many legs to use.
type Config struct {
	// TCPAddr is the concentrator's TCP tunnel endpoint, "host:port".
	TCPAddr string
	// UDPAddr is the first UDP tunnel endpoint. Leg N connects to port+N.
	// Empty disables the UDP legs.
	UDPAddr string
	// TCPLegs and UDPLegs are how many of each to open. A real MU5252 opens
	// one of each per WAN.
	TCPLegs int
	UDPLegs int

	// IcgID is what the device would have in icg.conf as
	// AggregationServerTunIP. It is the session key, so two clients using the
	// same value share a session on the server.
	IcgID netip.Addr
	// ClientTunIP is the device's own tun0 address, one above IcgID in
	// practice. Reported in the handshake.
	ClientTunIP netip.Addr
	// MAC is the device identity the handshake carries. Zero value gets a
	// deterministic fake.
	MAC net.HardwareAddr

	Magic  uint32
	Logger *slog.Logger
}

func (c *Config) setDefaults() {
	if c.TCPLegs == 0 {
		c.TCPLegs = 1
	}
	if !c.IcgID.IsValid() {
		c.IcgID = netip.MustParseAddr("172.16.25.18")
	}
	if !c.ClientTunIP.IsValid() {
		c.ClientTunIP = netip.MustParseAddr("172.16.25.19")
	}
	if len(c.MAC) == 0 {
		c.MAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	}
	if c.Magic == 0 {
		c.Magic = icg.DefaultMagic
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// Client is a fake CPE. Not safe for concurrent Dial/Close, but the read pumps
// and Send are.
type Client struct {
	cfg Config
	log *slog.Logger

	mu   sync.Mutex
	legs []*Leg

	// Global uplink sequence spaces, one per direction per protocol, exactly
	// as the device keeps them (§10).
	tcpSeq atomic.Uint32
	udpSeq atomic.Uint32

	// Downlink frames land here, tagged with the leg they arrived on.
	Frames chan Received

	// Counters for the caller to assert on.
	Stats Counters

	closed atomic.Bool
}

// Counters records what the server sent us, which is what a probe asserts on.
type Counters struct {
	ServerHandshakeAcks atomic.Uint64
	TunnelDetects       atomic.Uint64
	CumulativeAcks      atomic.Uint64
	RetransmitRequests  atomic.Uint64
	RTTSyncAcks         atomic.Uint64
	TCPDownFrames       atomic.Uint64
	UDPDownFrames       atomic.Uint64
	Unknown             atomic.Uint64
	Resyncs             atomic.Uint64
}

// Received is one downlink frame with its body owned by the receiver.
type Received struct {
	Leg   *Leg
	Frame *icg.Frame
	At    time.Time
}

// Leg is one WAN path.
type Leg struct {
	Index int
	Kind  string // "tcp" | "udp"
	conn  net.Conn
	mu    sync.Mutex
}

func (l *Leg) String() string { return fmt.Sprintf("%s%d", l.Kind, l.Index) }

// New creates a client. Nothing is connected until Dial.
func New(cfg Config) *Client {
	cfg.setDefaults()
	return &Client{
		cfg:    cfg,
		log:    cfg.Logger.With("component", "icg-client"),
		Frames: make(chan Received, 1024),
	}
}

// Dial opens every leg and starts reading them.
func (c *Client) Dial() error {
	for i := 0; i < c.cfg.TCPLegs; i++ {
		conn, err := net.DialTimeout("tcp", c.cfg.TCPAddr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("tcp leg %d: %w", i, err)
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		leg := &Leg{Index: i, Kind: "tcp", conn: conn}
		c.addLeg(leg)
		go c.readStream(leg)
	}
	if c.cfg.UDPAddr != "" && c.cfg.UDPLegs > 0 {
		host, portStr, err := net.SplitHostPort(c.cfg.UDPAddr)
		if err != nil {
			return fmt.Errorf("bad -udp address: %w", err)
		}
		var base int
		if _, err := fmt.Sscanf(portStr, "%d", &base); err != nil {
			return fmt.Errorf("bad -udp port: %w", err)
		}
		for i := 0; i < c.cfg.UDPLegs; i++ {
			addr := net.JoinHostPort(host, fmt.Sprint(base+i))
			conn, err := net.Dial("udp", addr)
			if err != nil {
				return fmt.Errorf("udp leg %d (%s): %w", i, addr, err)
			}
			leg := &Leg{Index: i, Kind: "udp", conn: conn}
			c.addLeg(leg)
			go c.readDatagrams(leg)
		}
	}
	return nil
}

func (c *Client) addLeg(l *Leg) {
	c.mu.Lock()
	c.legs = append(c.legs, l)
	c.mu.Unlock()
}

// Legs returns the open legs of a kind ("" for all).
func (c *Client) Legs(kind string) []*Leg {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*Leg, 0, len(c.legs))
	for _, l := range c.legs {
		if kind == "" || l.Kind == kind {
			out = append(out, l)
		}
	}
	return out
}

// Close shuts every leg.
func (c *Client) Close() {
	if c.closed.Swap(true) {
		return
	}
	for _, l := range c.Legs("") {
		_ = l.conn.Close()
	}
}

// Send writes a frame on a specific leg, stamping the session identity.
func (c *Client) Send(l *Leg, f *icg.Frame) error {
	f.Magic = c.cfg.Magic
	f.IcgID = tunIPWord(c.cfg.IcgID)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.conn.Write(f.Encode())
	return err
}

// tunIPWord encodes the address the way the device does: htonl of the
// in_addr, i.e. the four bytes in network order read as a host uint32 (§2).
func tunIPWord(a netip.Addr) uint32 {
	b := a.As4()
	return binary.LittleEndian.Uint32(b[:])
}

func (c *Client) readStream(l *Leg) {
	sr := icg.NewStreamReader(l.conn, c.cfg.Magic)
	for {
		f, err := sr.Next()
		if err != nil {
			if !c.closed.Load() && !errors.Is(err, net.ErrClosed) {
				c.log.Debug("leg read ended", "leg", l, "err", err)
			}
			c.Stats.Resyncs.Add(uint64(sr.Resyncs))
			return
		}
		c.deliver(l, f)
	}
}

func (c *Client) readDatagrams(l *Leg) {
	buf := make([]byte, 65535)
	for {
		n, err := l.conn.Read(buf)
		if err != nil {
			if !c.closed.Load() && !errors.Is(err, net.ErrClosed) {
				c.log.Debug("udp leg read ended", "leg", l, "err", err)
			}
			return
		}
		for off := 0; off < n; {
			f, used, derr := icg.Decode(buf[off:n], c.cfg.Magic)
			if derr != nil {
				break
			}
			off += used
			c.deliver(l, f)
		}
	}
}

// deliver copies the frame out of the read buffer, counts it, and queues it.
func (c *Client) deliver(l *Leg, f *icg.Frame) {
	cp := *f
	if len(f.Body) > 0 {
		cp.Body = append(make([]byte, 0, len(f.Body)), f.Body...)
	}
	c.count(&cp)
	select {
	case c.Frames <- Received{Leg: l, Frame: &cp, At: time.Now()}:
	default:
		// A probe that stops reading is not worth stalling the tunnel for.
	}
}

func (c *Client) count(f *icg.Frame) {
	switch f.Type {
	case icg.TypeHandshake:
		switch f.Opcode {
		case icg.HSServerAck:
			c.Stats.ServerHandshakeAcks.Add(1)
		case icg.HSRTTSyncAck:
			c.Stats.RTTSyncAcks.Add(1)
		}
	case icg.TypeAck:
		switch f.Opcode {
		case icg.AckTunnelDetect:
			c.Stats.TunnelDetects.Add(1)
		case icg.AckTCPCumulative, icg.AckUDPCumulative:
			c.Stats.CumulativeAcks.Add(1)
		case icg.AckTCPRetranRange, icg.AckUDPRetranRange,
			icg.AckTCPRetranOne, icg.AckUDPRetranOne:
			c.Stats.RetransmitRequests.Add(1)
		}
	case icg.TypeTCPDown:
		c.Stats.TCPDownFrames.Add(1)
	case icg.TypeUDP:
		c.Stats.UDPDownFrames.Add(1)
	default:
		c.Stats.Unknown.Add(1)
	}
}

// ---------------------------------------------------------------------------
// the handshake — §4, §6
// ---------------------------------------------------------------------------

// Handshake performs the exchange the device performs: send
// ICG_HANDSHAKE_REQ_WITH_CONFIG on every TCP leg, wait for
// ICG_SERVER_HANDSHAKE_ACK, then send ICG_CONFIRM_SERVER_ACK on every leg.
func (c *Client) Handshake(timeout time.Duration) error {
	legs := c.Legs("tcp")
	if len(legs) == 0 {
		return errors.New("no tcp legs")
	}
	req := c.handshakeReqBody()
	for _, l := range legs {
		if err := c.Send(l, &icg.Frame{
			Type: icg.TypeHandshake, Opcode: icg.HSReqWithConfig, Body: req,
		}); err != nil {
			return fmt.Errorf("send handshake on %s: %w", l, err)
		}
	}

	if _, err := c.WaitFor(timeout, func(r Received) bool {
		return r.Frame.Type == icg.TypeHandshake && r.Frame.Opcode == icg.HSServerAck
	}); err != nil {
		return fmt.Errorf("no ICG_SERVER_HANDSHAKE_ACK: %w", err)
	}

	// The device sends the confirm on every valid tunnel, carrying the fake
	// ping (§4.2) with that tunnel's id.
	for i, l := range legs {
		if err := c.Send(l, &icg.Frame{
			Type: icg.TypeHandshake, Opcode: icg.HSConfirmAck, Body: FakePing(c.cfg.ClientTunIP, i),
		}); err != nil {
			return fmt.Errorf("send confirm on %s: %w", l, err)
		}
	}
	return nil
}

// handshakeReqBody builds the 50-byte ICG_HANDSHAKE_REQ_WITH_CONFIG payload.
// The server never parses past the MAC and tun IP (§6), so the remaining
// device telemetry is left zero rather than invented.
func (c *Client) handshakeReqBody() []byte {
	b := make([]byte, icg.HandshakeReqLen)
	copy(b[0:6], c.cfg.MAC)
	ip := c.cfg.ClientTunIP.As4()
	copy(b[6:10], ip[:])
	return b
}

// Keepalive sends ICG_KEEPALIVE on a leg, the way the device does at ~1 Hz.
func (c *Client) Keepalive(l *Leg) error {
	return c.Send(l, &icg.Frame{
		Type: icg.TypeHandshake, Opcode: icg.HSKeepalive,
		Body: FakePing(c.cfg.ClientTunIP, l.Index),
	})
}

// RTTSync sends one ICG_UDP_CHNN_RTT_SYNC on a UDP leg and waits for the
// server's ack, returning the measured round trip. It also verifies the thing
// that matters: that the server echoed our clock unchanged (§4.3).
func (c *Client) RTTSync(l *Leg, seq uint32, timeout time.Duration) (time.Duration, error) {
	sent := time.Now()
	body := icg.RTTBody{
		Seq:      seq,
		ClientMS: uint64(sent.UnixMilli()),
		Trailer:  [5]byte{0x04, 0x01, 0x01, 0x00, 0x00},
	}
	if err := c.Send(l, &icg.Frame{
		Type: icg.TypeHandshake, Opcode: icg.HSRTTSync, Body: body.AppendTo(nil),
	}); err != nil {
		return 0, err
	}
	r, err := c.WaitFor(timeout, func(rx Received) bool {
		if rx.Frame.Type != icg.TypeHandshake || rx.Frame.Opcode != icg.HSRTTSyncAck {
			return false
		}
		got, perr := icg.ParseRTTBody(rx.Frame.Body)
		return perr == nil && got.Seq == seq
	})
	if err != nil {
		return 0, err
	}
	got, _ := icg.ParseRTTBody(r.Frame.Body)
	if got.ClientMS != body.ClientMS {
		return 0, fmt.Errorf("server altered our timestamp: sent %d, got %d back — "+
			"the device would compute a nonsense RTT and stop using this leg",
			body.ClientMS, got.ClientMS)
	}
	if got.ServerMS == 0 {
		return 0, errors.New("server did not fill in its own timestamp")
	}
	// Echo it back as the device does, so the server can measure its own RTT.
	_ = c.Send(l, &icg.Frame{Type: icg.TypeHandshake, Opcode: icg.HSRTTAck, Body: rx(r)})
	return time.Since(sent), nil
}

func rx(r Received) []byte { return r.Frame.Body }

// ---------------------------------------------------------------------------
// TCP flows — §7
// ---------------------------------------------------------------------------

// Flow is a proxied TCP connection through the tunnel: the device's view of one
// LAN client talking to one internet host.
type Flow struct {
	c    *Client
	flow icg.Flow
}

// OpenFlow announces a new LAN connection to the concentrator.
func (c *Client) OpenFlow(client, server netip.AddrPort) (*Flow, error) {
	f := &Flow{c: c, flow: icg.Flow{Client: client, Server: server}}
	return f, f.send(c.NextTCPSeq(), icg.TCPConnect, nil, 0)
}

// Write sends stream data with the next sequence number. Pass legIndex to pin
// a leg, or -1 to round-robin.
func (f *Flow) Write(b []byte, legIndex int) error {
	return f.send(f.c.NextTCPSeq(), icg.TCPPayload, b, legIndex)
}

// WriteAt sends stream data with a sequence number the caller chose. This is
// what makes reassembly testable: allocate ascending numbers with NextTCPSeq,
// then transmit them in whatever order you like. Writing with Write instead
// would allocate at transmit time, so "out of order" would really mean "the
// bytes are in a different order", which is a different (and uninteresting)
// thing to test.
func (f *Flow) WriteAt(seq uint32, b []byte, legIndex int) error {
	return f.send(seq, icg.TCPPayload, b, legIndex)
}

// Close tells the concentrator the LAN side went away.
func (f *Flow) Close() error { return f.send(f.c.NextTCPSeq(), icg.TCPDisconnect, nil, 0) }

// NextTCPSeq allocates the next number from the global uplink TCP sequence
// space, the way the device does (§10).
func (c *Client) NextTCPSeq() uint32 { return c.tcpSeq.Add(1) - 1 }

func (f *Flow) send(seq uint32, op icg.TCPOpcode, data []byte, legIndex int) error {
	legs := f.c.Legs("tcp")
	if len(legs) == 0 {
		return errors.New("no tcp legs")
	}
	var leg *Leg
	if legIndex >= 0 && legIndex < len(legs) {
		leg = legs[legIndex]
	} else {
		leg = legs[int(seq)%len(legs)]
	}
	body := icg.TCPBody{
		Seq: seq, Opcode: op,
		Src: f.flow.Client, Dst: f.flow.Server, Data: data,
	}
	return f.c.Send(leg, &icg.Frame{Type: icg.TypeTCPUp, Body: body.AppendTo(nil)})
}

// Tuple reports the flow's 5-tuple.
func (f *Flow) Tuple() icg.Flow { return f.flow }

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// WaitFor returns the first received frame matching pred.
func (c *Client) WaitFor(timeout time.Duration, pred func(Received) bool) (Received, error) {
	deadline := time.After(timeout)
	for {
		select {
		case r := <-c.Frames:
			if pred(r) {
				return r, nil
			}
		case <-deadline:
			return Received{}, fmt.Errorf("timed out after %s", timeout)
		}
	}
}

// CollectFlowData gathers downlink payload for one flow and reassembles it by
// the server's global downlink sequence number.
//
// It must reorder, not assume: the concentrator stripes downlink frames across
// legs too, so on a real link (this was found on a 700 ms satellite hop) the
// first frame to arrive is not the first frame sent. Reassembly therefore
// starts from the LOWEST sequence number seen rather than the first one
// received — anchoring on the first arrival silently loses everything below it,
// which on a link with reordering means losing the whole response.
//
// done is called with the bytes so far after each frame; return true to stop.
func (c *Client) CollectFlowData(flow icg.Flow, timeout time.Duration, done func([]byte) bool) ([]byte, error) {
	deadline := time.After(timeout)
	frames := map[uint32][]byte{}
	closed := false

	// assemble walks contiguously from the lowest sequence number held.
	assemble := func() []byte {
		if len(frames) == 0 {
			return nil
		}
		lo := ^uint32(0)
		first := true
		for s := range frames {
			if first || int32(s-lo) < 0 {
				lo, first = s, false
			}
		}
		var out []byte
		for s := lo; ; s++ {
			chunk, ok := frames[s]
			if !ok {
				break
			}
			out = append(out, chunk...)
		}
		return out
	}

	for {
		select {
		case r := <-c.Frames:
			if r.Frame.Type != icg.TypeTCPDown {
				continue
			}
			b, err := icg.ParseTCPBody(r.Frame.Body)
			if err != nil {
				continue
			}
			// A downlink frame carries the tuple server-first, so flip it back.
			if (icg.Flow{Client: b.Dst, Server: b.Src}) != flow {
				continue
			}
			switch b.Opcode {
			case icg.TCPPayload:
				frames[b.Seq] = append([]byte(nil), b.Data...)
			case icg.TCPDisconnect:
				frames[b.Seq] = nil
				closed = true
			default:
				continue
			}
			out := assemble()
			if done != nil && done(out) {
				return out, nil
			}
			if closed && done == nil {
				return out, nil
			}
		case <-deadline:
			out := assemble()
			if done != nil && !done(out) {
				return out, fmt.Errorf("timed out after %s: %d frames held, %d bytes assembled%s",
					timeout, len(frames), len(out), seqNote(frames))
			}
			return out, nil
		}
	}
}

// CountFlowData counts unique downlink payload bytes for one flow without
// retaining the payload. It is intended for sustained-throughput probes where
// CollectFlowData's full reassembly would consume memory proportional to the
// download size. It retains only the sequence numbers needed to reject
// retransmitted frames. Sequence numbers are global and frames can arrive on
// any leg, so ordering is deliberately irrelevant.
func (c *Client) CountFlowData(flow icg.Flow, timeout time.Duration, atLeast int64) (int64, error) {
	if atLeast <= 0 {
		return 0, fmt.Errorf("atLeast must be positive, got %d", atLeast)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	seen := make(map[uint32]struct{})
	var total int64
	closed := false
	for {
		select {
		case r := <-c.Frames:
			if r.Frame.Type != icg.TypeTCPDown {
				continue
			}
			b, err := icg.ParseTCPBody(r.Frame.Body)
			if err != nil {
				continue
			}
			// A downlink frame carries the tuple server-first, so flip it back.
			if (icg.Flow{Client: b.Dst, Server: b.Src}) != flow {
				continue
			}
			switch b.Opcode {
			case icg.TCPPayload:
				if _, ok := seen[b.Seq]; ok {
					continue
				}
				seen[b.Seq] = struct{}{}
				total += int64(len(b.Data))
				if total >= atLeast {
					return total, nil
				}
			case icg.TCPDisconnect:
				// The disconnect can arrive before an earlier payload striped over
				// another leg. Remember it, but keep collecting until the target or
				// timeout rather than reporting a false short read immediately.
				closed = true
			}
		case <-timer.C:
			if closed {
				return total, fmt.Errorf("flow closed after %d bytes, wanted at least %d", total, atLeast)
			}
			return total, fmt.Errorf("timed out after %s with %d bytes, wanted at least %d", timeout, total, atLeast)
		}
	}
}

// seqNote describes what we are holding, so a timeout says something useful
// rather than just "0 bytes".
func seqNote(frames map[uint32][]byte) string {
	if len(frames) == 0 {
		return " (no frames for this flow at all)"
	}
	seqs := make([]uint32, 0, len(frames))
	for s := range frames {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return int32(seqs[i]-seqs[j]) < 0 })
	return fmt.Sprintf(" (downlink seqs held: %v)", seqs)
}

// FakePing builds the synthesised IPv4/ICMP echo that ICG_KEEPALIVE and
// ICG_CONFIRM_SERVER_ACK carry, with the tunnel id in the TLV the device puts
// at the front of the ICMP data area (§4.2).
func FakePing(src netip.Addr, tunnelID int) []byte {
	p := make([]byte, 0x54)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], 0x54)
	p[8] = 0xff // TTL, as the device sets it
	p[9] = 1    // ICMP
	s := src.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], []byte{8, 8, 8, 8}) // hardcoded in the device too
	p[20] = 8                          // echo request
	binary.BigEndian.PutUint16(p[24:], 0x74cf)
	binary.BigEndian.PutUint16(p[26:], uint16(tunnelID))
	p[28], p[29] = 0x02, 0x04
	binary.LittleEndian.PutUint32(p[30:], uint32(tunnelID))
	for i := 34; i < len(p); i++ {
		p[i] = 0xa5
	}
	binary.BigEndian.PutUint16(p[10:], ipChecksum(p[:20]))
	binary.BigEndian.PutUint16(p[22:], ipChecksum(p[20:]))
	return p
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
