package concentrator

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/iangcarroll/zte-coord/icg"
)

// These tests drive the concentrator with a fake zte_icg_agg: a client that
// speaks the framing from ICG_WIRE_PROTOCOL.md over real sockets. They are the
// only way to exercise the parts that no capture covers — the handshake, the
// proxy, striping across legs, and retransmission.

const testTunIP = 0x1219_10ac // 172.16.25.18 in the byte order the client sends

func testLogger(t *testing.T) *slog.Logger {
	lvl := slog.LevelWarn
	if testing.Verbose() {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// harness is a running concentrator plus the addresses it bound.
type harness struct {
	t   *testing.T
	srv *Server
	tcp string
	udp []string
}

func startHarness(t *testing.T, tweak func(*Config)) *harness {
	t.Helper()
	cfg := Config{
		TCPAddr:           "127.0.0.1:0",
		UDPLegs:           0, // most tests do not need UDP legs
		Logger:            testLogger(t),
		KeepaliveInterval: time.Hour, // keep test output quiet unless asked
		AckInterval:       20 * time.Millisecond,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	srv := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.Run(ctx) }()

	select {
	case <-srv.Ready():
	case err := <-errc:
		cancel()
		t.Fatalf("concentrator did not bind: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("concentrator did not bind")
	}

	h := &harness{t: t, srv: srv, tcp: srv.TCPAddr().String()}
	for _, a := range srv.UDPAddrs() {
		h.udp = append(h.udp, a.String())
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("server exited with %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	})
	return h
}

// leg is one WAN path of the fake client.
type leg struct {
	t    *testing.T
	conn net.Conn
	sr   *icg.StreamReader
	kind string
	mu   sync.Mutex
}

func (h *harness) dialTCPLeg() *leg {
	h.t.Helper()
	c, err := net.Dial("tcp", h.tcp)
	if err != nil {
		h.t.Fatalf("dial leg: %v", err)
	}
	h.t.Cleanup(func() { c.Close() })
	return &leg{t: h.t, conn: c, sr: icg.NewStreamReader(c, 0), kind: "tcp"}
}

func (h *harness) dialUDPLeg(idx int) *leg {
	h.t.Helper()
	c, err := net.Dial("udp", h.udp[idx])
	if err != nil {
		h.t.Fatalf("dial udp leg: %v", err)
	}
	h.t.Cleanup(func() { c.Close() })
	return &leg{t: h.t, conn: c, kind: "udp"}
}

func (l *leg) send(f *icg.Frame) {
	l.t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	f.IcgID = testTunIP
	if _, err := l.conn.Write(f.Encode()); err != nil {
		l.t.Fatalf("leg write: %v", err)
	}
}

// recv waits for the next frame, failing the test on timeout.
func (l *leg) recv(timeout time.Duration) *icg.Frame {
	l.t.Helper()
	f, err := l.tryRecv(timeout)
	if err != nil {
		l.t.Fatalf("leg recv: %v", err)
	}
	return f
}

func (l *leg) tryRecv(timeout time.Duration) (*icg.Frame, error) {
	_ = l.conn.SetReadDeadline(time.Now().Add(timeout))
	if l.kind == "udp" {
		buf := make([]byte, 65535)
		n, err := l.conn.Read(buf)
		if err != nil {
			return nil, err
		}
		f, _, err := icg.Decode(buf[:n], 0)
		return f, err
	}
	return l.sr.Next()
}

// recvUntil returns the first frame matching pred, skipping the control chatter
// (ACKs, tunnel-detects) that the concentrator emits on its own schedule.
func (l *leg) recvUntil(timeout time.Duration, pred func(*icg.Frame) bool) *icg.Frame {
	l.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			l.t.Fatalf("timed out waiting for a matching frame")
		}
		f, err := l.tryRecv(left)
		if err != nil {
			l.t.Fatalf("recvUntil: %v", err)
		}
		if pred(f) {
			return f
		}
	}
}

// handshake performs the full three-step exchange of §6 and asserts the
// server's half of it.
func (l *leg) handshake() {
	l.t.Helper()
	body := make([]byte, icg.HandshakeReqLen)
	copy(body, []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}) // MAC
	copy(body[6:], []byte{172, 16, 25, 19})                // client tun IP
	l.send(&icg.Frame{Type: icg.TypeHandshake, Opcode: icg.HSReqWithConfig, Body: body})

	ack := l.recvUntil(2*time.Second, func(f *icg.Frame) bool {
		return f.Type == icg.TypeHandshake
	})
	if ack.Opcode != icg.HSServerAck {
		l.t.Fatalf("handshake: got opcode %d (%s), want ICG_SERVER_HANDSHAKE_ACK",
			ack.Opcode, icg.OpcodeName(ack.Type, ack.Opcode))
	}
	// The client ignores this body; the concentrator should not waste bytes.
	if len(ack.Body) != 0 {
		l.t.Errorf("ICG_SERVER_HANDSHAKE_ACK carried %d body bytes; the client ignores them", len(ack.Body))
	}
	if ack.IcgID != testTunIP {
		l.t.Errorf("server echoed tun_ip %#x, want %#x", ack.IcgID, uint32(testTunIP))
	}

	l.send(&icg.Frame{Type: icg.TypeHandshake, Opcode: icg.HSConfirmAck, Body: fakePing(3)})
}

// fakePing builds the synthesised IPv4/ICMP echo the client's keepalive and
// confirm frames carry, with a tunnel id embedded the way §4.2 describes.
func fakePing(tunnelID uint8) []byte {
	p := make([]byte, 0x54)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], 0x54)
	p[8] = 0xff
	p[9] = 1 // ICMP
	copy(p[12:16], []byte{172, 16, 25, 19})
	copy(p[16:20], []byte{8, 8, 8, 8})
	p[20] = 8 // echo request
	binary.BigEndian.PutUint16(p[24:], 0x74cf)
	binary.BigEndian.PutUint16(p[26:], 0x078d)
	p[28], p[29] = 0x02, 0x04
	binary.LittleEndian.PutUint32(p[30:], uint32(tunnelID))
	for i := 34; i < len(p); i++ {
		p[i] = 0xa5
	}
	binary.BigEndian.PutUint16(p[10:], checksum(p[:20]))
	return p
}

// ---------------------------------------------------------------------------

func TestHandshake(t *testing.T) {
	h := startHarness(t, nil)
	l := h.dialTCPLeg()
	l.handshake()

	// After the handshake, the concentrator should be tracking exactly one
	// session, keyed by the tun IP.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ss := h.srv.Sessions()
		if len(ss) == 1 {
			if got := ss[0].IcgID(); got != "172.16.25.18" {
				t.Errorf("session key = %s, want 172.16.25.18", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sessions = %d, want 1", len(ss))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A repeated handshake must be answered, not ignored: the client re-sends
// ICG_HANDSHAKE_REQ_WITH_CONFIG once a second until it gets an ack, and it
// resets its sequence spaces when it does.
func TestHandshakeIsIdempotent(t *testing.T) {
	h := startHarness(t, nil)
	l := h.dialTCPLeg()
	for i := 0; i < 3; i++ {
		l.handshake()
	}
}

func TestKeepaliveIsAnswered(t *testing.T) {
	h := startHarness(t, nil)
	l := h.dialTCPLeg()
	l.handshake()

	l.send(&icg.Frame{Type: icg.TypeHandshake, Opcode: icg.HSKeepalive, Body: fakePing(7)})
	got := l.recvUntil(2*time.Second, func(f *icg.Frame) bool {
		return f.Type == icg.TypeAck && f.Opcode == icg.AckTunnelDetect
	})
	if len(got.Body) != 0 {
		t.Errorf("tunnel detect carried %d body bytes", len(got.Body))
	}
}

// ---------------------------------------------------------------------------
// TCP proxying
// ---------------------------------------------------------------------------

// echoServer is a stand-in for whatever the LAN client was really talking to.
func echoServer(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func TestTCPProxyRoundTrip(t *testing.T) {
	upstream := echoServer(t)
	h := startHarness(t, nil)
	l := h.dialTCPLeg()
	l.handshake()

	flow := icg.Flow{
		Client: netip.MustParseAddrPort("192.168.0.245:62701"),
		Server: upstream,
	}
	sendTCP(l, 1, flow, icg.TCPConnect, nil)
	sendTCP(l, 2, flow, icg.TCPPayload, []byte("hello concentrator"))

	body := recvTCPPayload(t, l, 3*time.Second)
	if string(body.Data) != "hello concentrator" {
		t.Fatalf("echoed %q", body.Data)
	}
	// The downlink tuple must be the uplink's, swapped: that is what lets the
	// client match it to the right LAN socket.
	if body.Src != flow.Server || body.Dst != flow.Client {
		t.Errorf("downlink tuple %s -> %s, want %s -> %s", body.Src, body.Dst, flow.Server, flow.Client)
	}
}

// The downlink has its own global sequence space starting from zero, and it
// must increment by one per frame regardless of which flow the data belongs to.
func TestDownlinkSequenceIsGlobalAndMonotonic(t *testing.T) {
	upstream := echoServer(t)
	h := startHarness(t, nil)
	l := h.dialTCPLeg()
	l.handshake()

	flows := []icg.Flow{
		{Client: netip.MustParseAddrPort("192.168.0.245:1001"), Server: upstream},
		{Client: netip.MustParseAddrPort("192.168.0.246:1002"), Server: upstream},
	}
	var up uint32 = 1
	for _, f := range flows {
		sendTCP(l, up, f, icg.TCPConnect, nil)
		up++
	}
	for i, f := range flows {
		sendTCP(l, up, f, icg.TCPPayload, []byte{byte('a' + i)})
		up++
	}

	seen := map[uint32]bool{}
	for i := 0; i < 2; i++ {
		b := recvTCPPayload(t, l, 3*time.Second)
		if seen[b.Seq] {
			t.Fatalf("downlink seq %d reused", b.Seq)
		}
		seen[b.Seq] = true
	}
	// Two frames, two distinct sequence numbers, and they come from one
	// counter shared by both flows: so {0,1}.
	if !seen[0] || !seen[1] {
		t.Fatalf("downlink seqs = %v, want a shared counter starting at 0", seen)
	}
}

func TestTCPDisconnectClosesUpstream(t *testing.T) {
	// A server that reports when its connection closes.
	closed := make(chan struct{}, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c)
		c.Close()
		closed <- struct{}{}
	}()

	h := startHarness(t, nil)
	l := h.dialTCPLeg()
	l.handshake()
	flow := icg.Flow{
		Client: netip.MustParseAddrPort("192.168.0.245:5000"),
		Server: netip.MustParseAddrPort(ln.Addr().String()),
	}
	sendTCP(l, 1, flow, icg.TCPConnect, nil)
	sendTCP(l, 2, flow, icg.TCPPayload, []byte("x"))
	sendTCP(l, 3, flow, icg.TCPDisconnect, nil)

	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream connection was not closed")
	}
}

// A dial that fails must produce a DISCONNECT rather than silence, or the LAN
// client hangs until its own timeout.
func TestUnreachableUpstreamReportsDisconnect(t *testing.T) {
	// Port 1 on loopback: nothing listens, connection refused immediately.
	h := startHarness(t, nil)
	l := h.dialTCPLeg()
	l.handshake()
	flow := icg.Flow{
		Client: netip.MustParseAddrPort("192.168.0.245:5001"),
		Server: netip.MustParseAddrPort("127.0.0.1:1"),
	}
	sendTCP(l, 1, flow, icg.TCPConnect, nil)

	f := l.recvUntil(5*time.Second, func(f *icg.Frame) bool {
		if f.Type != icg.TypeTCPDown {
			return false
		}
		b, err := icg.ParseTCPBody(f.Body)
		return err == nil && b.Opcode == icg.TCPDisconnect
	})
	b, _ := icg.ParseTCPBody(f.Body)
	if b.Dst != flow.Client {
		t.Errorf("disconnect addressed to %s, want %s", b.Dst, flow.Client)
	}
}

// The egress guard is the only thing standing between a concentrator and being
// an open proxy, since the protocol itself has no authentication.
func TestEgressGuardIsHonoured(t *testing.T) {
	upstream := echoServer(t)
	h := startHarness(t, func(c *Config) {
		c.DialContextTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("denied by policy")
		}
	})
	l := h.dialTCPLeg()
	l.handshake()
	flow := icg.Flow{
		Client: netip.MustParseAddrPort("192.168.0.245:5002"),
		Server: upstream,
	}
	sendTCP(l, 1, flow, icg.TCPConnect, nil)
	sendTCP(l, 2, flow, icg.TCPPayload, []byte("should not arrive"))

	f := l.recvUntil(3*time.Second, func(f *icg.Frame) bool {
		if f.Type != icg.TypeTCPDown {
			return false
		}
		b, err := icg.ParseTCPBody(f.Body)
		return err == nil && b.Opcode == icg.TCPDisconnect
	})
	if f == nil {
		t.Fatal("expected a disconnect")
	}
}

// ---------------------------------------------------------------------------
// Reassembly across legs
// ---------------------------------------------------------------------------

// TestStripedOutOfOrderDeliversInOrder is the whole point of the protocol: two
// WANs, one flow, packets arriving in the wrong order, and a byte stream that
// must come out intact.
func TestStripedOutOfOrderDeliversInOrder(t *testing.T) {
	// A server that reads a fixed number of bytes and reports what it got.
	got := make(chan string, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		got <- string(buf)
	}()

	h := startHarness(t, nil)
	legA := h.dialTCPLeg()
	legA.handshake()
	legB := h.dialTCPLeg()
	// A second leg does not re-handshake; it just starts carrying frames with
	// the same tun_ip, which is exactly what the client does per WAN.
	legB.send(&icg.Frame{Type: icg.TypeHandshake, Opcode: icg.HSKeepalive, Body: fakePing(2)})

	flow := icg.Flow{
		Client: netip.MustParseAddrPort("192.168.0.245:6000"),
		Server: netip.MustParseAddrPort(ln.Addr().String()),
	}
	sendTCP(legA, 100, flow, icg.TCPConnect, nil)

	// "abcd", one byte per frame, deliberately scrambled and split across legs.
	sendTCP(legB, 104, flow, icg.TCPPayload, []byte("d"))
	sendTCP(legA, 102, flow, icg.TCPPayload, []byte("b"))
	sendTCP(legB, 103, flow, icg.TCPPayload, []byte("c"))
	sendTCP(legA, 101, flow, icg.TCPPayload, []byte("a"))

	select {
	case s := <-got:
		if s != "abcd" {
			t.Fatalf("upstream received %q, want \"abcd\" — reassembly is broken", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the reassembled stream")
	}
}

// A permanently lost sequence number must not wedge the tunnel: after the skip
// timeout the concentrator has to step over it, exactly as the client does.
func TestPermanentGapIsSkipped(t *testing.T) {
	got := make(chan string, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 2)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		got <- string(buf)
	}()

	h := startHarness(t, func(c *Config) {
		c.Reorder = ReorderConfig{RetransmitAfter: 20 * time.Millisecond, SkipAfter: 150 * time.Millisecond}
	})
	l := h.dialTCPLeg()
	l.handshake()

	flow := icg.Flow{
		Client: netip.MustParseAddrPort("192.168.0.245:6001"),
		Server: netip.MustParseAddrPort(ln.Addr().String()),
	}
	sendTCP(l, 10, flow, icg.TCPConnect, nil)
	sendTCP(l, 11, flow, icg.TCPPayload, []byte("a"))
	// 12 is never sent.
	sendTCP(l, 13, flow, icg.TCPPayload, []byte("c"))

	select {
	case s := <-got:
		if s != "ac" {
			t.Fatalf("upstream received %q, want \"ac\" after the gap was skipped", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel stalled on a permanently lost packet")
	}
}

// A gap must produce a retransmission request naming the missing sequence
// numbers, in the fixed 204-byte layout the client's parser expects.
func TestGapProducesRetransmitRequest(t *testing.T) {
	upstream := echoServer(t)
	h := startHarness(t, func(c *Config) {
		c.Reorder = ReorderConfig{RetransmitAfter: 20 * time.Millisecond, SkipAfter: time.Hour}
	})
	l := h.dialTCPLeg()
	l.handshake()

	flow := icg.Flow{Client: netip.MustParseAddrPort("192.168.0.245:6002"), Server: upstream}
	sendTCP(l, 50, flow, icg.TCPConnect, nil)
	sendTCP(l, 54, flow, icg.TCPPayload, []byte("z")) // 51,52,53 missing

	req := l.recvUntil(3*time.Second, func(f *icg.Frame) bool {
		return f.Type == icg.TypeAck && f.Opcode == icg.AckTCPRetranRange
	})
	if len(req.Body) != icg.SeqListLen {
		t.Errorf("retransmit request body is %d bytes, want %d — the client's parser is strict about this",
			len(req.Body), icg.SeqListLen)
	}
	seqs, err := icg.ParseSeqList(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{51, 52, 53}
	if len(seqs) != len(want) {
		t.Fatalf("requested %v, want %v", seqs, want)
	}
	for i := range want {
		if seqs[i] != want[i] {
			t.Fatalf("requested %v, want %v", seqs, want)
		}
	}
	if req.Seq != want[0] {
		t.Errorf("header seq = %d, want the first requested seq %d", req.Seq, want[0])
	}
}

// The concentrator must serve the mirror case too: when the client asks us to
// resend, the frame has to come back byte-identical, because the client keys
// its reorder buffer on the sequence number inside it.
func TestServesRetransmitRequest(t *testing.T) {
	upstream := echoServer(t)
	h := startHarness(t, nil)
	l := h.dialTCPLeg()
	l.handshake()

	flow := icg.Flow{Client: netip.MustParseAddrPort("192.168.0.245:6003"), Server: upstream}
	sendTCP(l, 1, flow, icg.TCPConnect, nil)
	sendTCP(l, 2, flow, icg.TCPPayload, []byte("retransmit me"))

	first := recvTCPPayload(t, l, 3*time.Second)

	// Ask for it again by its downlink sequence number.
	req := &icg.Frame{Type: icg.TypeAck, Opcode: icg.AckTCPRetranRange, Seq: first.Seq}
	req.Body = icg.AppendSeqList(nil, []uint32{first.Seq})
	l.send(req)

	again := l.recvUntil(3*time.Second, func(f *icg.Frame) bool {
		if f.Type != icg.TypeTCPDown {
			return false
		}
		b, err := icg.ParseTCPBody(f.Body)
		return err == nil && b.Seq == first.Seq && b.Opcode == icg.TCPPayload
	})
	b, _ := icg.ParseTCPBody(again.Body)
	if string(b.Data) != "retransmit me" {
		t.Fatalf("retransmitted payload = %q", b.Data)
	}
}

func TestCumulativeAckIsSent(t *testing.T) {
	upstream := echoServer(t)
	h := startHarness(t, nil)
	l := h.dialTCPLeg()
	l.handshake()

	flow := icg.Flow{Client: netip.MustParseAddrPort("192.168.0.245:6004"), Server: upstream}
	sendTCP(l, 200, flow, icg.TCPConnect, nil)
	sendTCP(l, 201, flow, icg.TCPPayload, []byte("q"))

	ack := l.recvUntil(3*time.Second, func(f *icg.Frame) bool {
		return f.Type == icg.TypeAck && f.Opcode == icg.AckTCPCumulative
	})
	if ack.Seq != 201 {
		t.Errorf("cumulative ack = %d, want 201", ack.Seq)
	}
	if len(ack.Body) != 0 {
		t.Errorf("cumulative ack carried %d body bytes; the seq lives in the header", len(ack.Body))
	}
}

// ---------------------------------------------------------------------------
// UDP legs
// ---------------------------------------------------------------------------

func TestRTTSyncEchoesClientClock(t *testing.T) {
	// UDPBase 0 makes the kernel pick ephemeral ports, which is what we want
	// in a test.
	h := startHarness(t, func(c *Config) { c.UDPBase = 0; c.UDPLegs = 1 })
	l := h.dialUDPLeg(0)

	body := icg.RTTBody{
		Seq:      0x0fe8,
		ClientMS: 1_787_509_093_938,
		Trailer:  [5]byte{4, 1, 1, 0, 0},
	}
	l.send(&icg.Frame{Type: icg.TypeHandshake, Opcode: icg.HSRTTSync, Body: body.AppendTo(nil)})

	f := l.recvUntil(3*time.Second, func(f *icg.Frame) bool {
		return f.Type == icg.TypeHandshake && f.Opcode == icg.HSRTTSyncAck
	})
	got, err := icg.ParseRTTBody(f.Body)
	if err != nil {
		t.Fatal(err)
	}
	// This is the invariant that matters: mangle ClientMS and every leg looks
	// infinitely slow to the client's scheduler.
	if got.ClientMS != body.ClientMS {
		t.Errorf("ClientMS = %d, want it echoed unchanged (%d)", got.ClientMS, body.ClientMS)
	}
	if got.Seq != body.Seq {
		t.Errorf("Seq = %d, want %d", got.Seq, body.Seq)
	}
	if got.Trailer != body.Trailer {
		t.Errorf("Trailer = %x, want it echoed unchanged", got.Trailer)
	}
	if got.ServerMS == 0 {
		t.Error("ServerMS was not filled in")
	}
	if len(f.Body) != icg.RTTBodyLen {
		t.Errorf("reply body is %d bytes, want %d", len(f.Body), icg.RTTBodyLen)
	}
}

// TestUDPNATRoundTrip exercises the §8 path: a whole IPv4/UDP packet in, NAT
// out to a real socket, and a re-encapsulated reply back.
func TestUDPNATRoundTrip(t *testing.T) {
	// A UDP echo server.
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = uc.WriteToUDP(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()
	server := netip.MustParseAddrPort(uc.LocalAddr().String())

	h := startHarness(t, func(c *Config) { c.UDPBase = 0; c.UDPLegs = 1 })
	l := h.dialUDPLeg(0)

	inside := netip.MustParseAddrPort("172.16.25.19:41234")
	pkt := buildUDPPacket(inside, server, 1, 64, []byte("ping"))
	l.send(&icg.Frame{Type: icg.TypeUDP, Opcode: 0, Seq: 1, Body: pkt})

	f := l.recvUntil(3*time.Second, func(f *icg.Frame) bool { return f.Type == icg.TypeUDP })

	ip, err := parseIPv4(f.Body)
	if err != nil {
		t.Fatalf("reply is not a valid IPv4 packet: %v", err)
	}
	if c := checksum(f.Body[:20]); c != 0 {
		t.Errorf("reply IPv4 checksum does not verify (%#x); the client hands these to the kernel", c)
	}
	d, err := parseUDP(ip)
	if err != nil {
		t.Fatal(err)
	}
	// The NAT must translate back so the inside host recognises the reply.
	if d.Dst != inside {
		t.Errorf("reply addressed to %s, want the inside host %s", d.Dst, inside)
	}
	if d.Src != server {
		t.Errorf("reply source %s, want %s", d.Src, server)
	}
	if string(d.Data) != "echo:ping" {
		t.Errorf("reply payload %q", d.Data)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func sendTCP(l *leg, seq uint32, flow icg.Flow, op icg.TCPOpcode, data []byte) {
	l.t.Helper()
	body := icg.TCPBody{Seq: seq, Opcode: op, Src: flow.Client, Dst: flow.Server, Data: data}
	l.send(&icg.Frame{Type: icg.TypeTCPUp, Opcode: 0, Seq: 0, Body: body.AppendTo(nil)})
}

func recvTCPPayload(t *testing.T, l *leg, timeout time.Duration) icg.TCPBody {
	t.Helper()
	f := l.recvUntil(timeout, func(f *icg.Frame) bool {
		if f.Type != icg.TypeTCPDown {
			return false
		}
		b, err := icg.ParseTCPBody(f.Body)
		return err == nil && b.Opcode == icg.TCPPayload
	})
	b, err := icg.ParseTCPBody(f.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
