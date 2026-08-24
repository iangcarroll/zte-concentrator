package concentrator

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/iangcarroll/zte-coord/icg"
)

// A Session is one CPE. It owns everything that must be serialised: the two
// global sequence spaces, the handshake state, the set of WAN legs, and the
// proxied flows.
//
// Concurrency model: exactly one goroutine (run) touches Session state. Legs
// hand frames in over the in channel; upstream sockets hand data back over the
// out channel. Nothing else reaches inside. That is what makes the sequence
// counters and the reassemblers correct without a lock around each of them.
//
// The session key is the tun_ip in the frame header. ZTE's dispatch hands each
// device its own tun pair — the concentrator side (the value in the header) and
// the client side, one above it — so that value identifies the device. When we
// run our own concentrator we choose the allocation ourselves.
type Session struct {
	srv   *Server
	tunIP uint32
	log   *slog.Logger

	in  chan sessionMsg
	out chan upstreamData

	cancel context.CancelFunc

	// lastRxUnixNano is read by the server's reaper from another goroutine, so
	// it is atomic; everything else in this struct belongs to run().
	lastRxUnixNano atomic.Int64

	// --- run-goroutine-only state below ---

	state icg.State
	legs  map[legKey]*Leg

	upTCP *Reorder[tcpChunk]
	upUDP *Reorder[[]byte]

	downTCPSeq uint32
	downUDPSeq uint32

	stashTCP *stash
	stashUDP *stash

	flows    map[icg.Flow]*tcpFlow
	udpFlows map[udpKey]*udpFlow

	lastTCPAck, lastUDPAck time.Time
	lastKeepalive          time.Time
	lastStats              time.Time
	lastPublish            time.Time
	createdAt              time.Time

	// Identity learned from ICG_HANDSHAKE_REQ_WITH_CONFIG.
	clientMAC   net.HardwareAddr
	clientTunIP netip.Addr

	// admitted is false until a handshake presents an allowed device MAC. With
	// no allowlist configured every session is admitted immediately.
	admitted bool

	stats Stats

	dropped atomic.Uint64

	// pub is the latest snapshot, published by run() and read by the API.
	pub atomicSnapshot
}

// Stats is a snapshot of one session's counters, for /metrics or a log line.
type Stats struct {
	FramesIn, FramesOut      uint64
	TCPFlows, TCPFlowsActive uint64
	UDPFlows, UDPFlowsActive uint64
	ICMPDropped              uint64
	RetransmitsServed        uint64
	RetransmitsRequested     uint64
	UnknownFrames            uint64
	Handshakes               uint64
	UpstreamDialFails        uint64
	Refused                  uint64
	RefusedFrames            uint64
}

type inbound struct {
	leg   *Leg
	frame *icg.Frame // Body is owned by the session (already copied)
	at    time.Time
}

// sessionMsg is everything that arrives from outside the session goroutine.
// Routing leg attach/detach through the same channel as frames means the leg
// table needs no lock and cannot be mutated mid-dispatch.
type sessionMsg struct {
	in      *inbound
	addLeg  *Leg
	dropLeg *legKey
}

// tcpChunk is a TCP data body with its payload owned by us rather than
// aliasing a read buffer.
type tcpChunk struct {
	flow icg.Flow
	op   icg.TCPOpcode
	data []byte
}

// upstreamData is one chunk travelling client-ward, produced by an upstream
// socket's reader goroutine. Exactly one of the fields is meaningful.
type upstreamData struct {
	// TCP
	flow       icg.Flow
	data       []byte
	closed     bool
	dialFailed bool
	isTCP      bool

	// UDP: a complete IPv4 packet, ready to encapsulate
	udpPacket []byte
}

func newSession(srv *Server, tunIP uint32) *Session {
	s := &Session{
		srv:   srv,
		tunIP: tunIP,
		log:   srv.log.With("icg_id", icgIDString(tunIP)),
		in:    make(chan sessionMsg, 512),
		out:   make(chan upstreamData, 512),

		legs:     make(map[legKey]*Leg),
		flows:    make(map[icg.Flow]*tcpFlow),
		udpFlows: make(map[udpKey]*udpFlow),

		createdAt: time.Now(),

		upTCP:    NewReorder[tcpChunk](srv.cfg.Reorder),
		upUDP:    NewReorder[[]byte](srv.cfg.Reorder),
		stashTCP: newStash(srv.cfg.StashLimit),
		stashUDP: newStash(srv.cfg.StashLimit),
	}
	return s
}

// post hands a received frame to the session goroutine. The frame's Body
// aliases the caller's read buffer, so it is copied here — this is the one
// place that ownership transfer happens.
func (s *Session) post(f *icg.Frame, leg *Leg) {
	cp := *f
	if len(f.Body) > 0 {
		cp.Body = append(make([]byte, 0, len(f.Body)), f.Body...)
	}
	now := time.Now()
	s.lastRxUnixNano.Store(now.UnixNano())
	msg := sessionMsg{in: &inbound{leg: leg, frame: &cp, at: now}}
	select {
	case s.in <- msg:
	case <-s.srv.ctx.Done():
	default:
		// The session goroutine is wedged or hopelessly behind. Dropping is
		// the honest failure mode: the peer's retransmission machinery exists
		// precisely for this, and blocking here would stall every other leg.
		s.dropped.Add(1)
	}
}

// attachLeg registers a WAN path with the session.
func (s *Session) attachLeg(l *Leg) {
	select {
	case s.in <- sessionMsg{addLeg: l}:
	case <-s.srv.ctx.Done():
	}
}

// detachLeg removes one.
func (s *Session) detachLeg(k legKey) {
	select {
	case s.in <- sessionMsg{dropLeg: &k}:
	case <-s.srv.ctx.Done():
	}
}

// IdleFor is how long since the last inbound frame. Safe from any goroutine.
func (s *Session) IdleFor() time.Duration {
	ns := s.lastRxUnixNano.Load()
	if ns == 0 {
		return 0
	}
	return time.Since(time.Unix(0, ns))
}

// stop ends the session goroutine and releases its sockets.
func (s *Session) stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// IcgID is the session key: the tun address ZTE's dispatch allocated to this
// device, rendered in network order.
func (s *Session) IcgID() string { return icgIDString(s.tunIP) }

// Dropped is how many inbound frames were shed because the session goroutine
// could not keep up. Non-zero means the concentrator is the bottleneck.
func (s *Session) Dropped() uint64 { return s.dropped.Load() }

// run is the session's single goroutine.
func (s *Session) run(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	// The tick drives everything time-based: retransmit requests, gap
	// expiry, cumulative ACKs and our own keepalives. The client tears the
	// session down after 30 s of silence and stops the daemon after 150 s
	// (ICG_WIRE_PROTOCOL.md §6), so this must keep running.
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	defer s.shutdown()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-s.in:
			switch {
			case msg.in != nil:
				s.handleFrame(*msg.in)
			case msg.addLeg != nil:
				s.legs[msg.addLeg.Key] = msg.addLeg
			case msg.dropLeg != nil:
				delete(s.legs, *msg.dropLeg)
			}
		case out := <-s.out:
			s.handleUpstream(out)
		case now := <-tick.C:
			s.tick(now)
		}
	}
}

func (s *Session) shutdown() {
	for _, f := range s.flows {
		f.close()
	}
	for _, f := range s.udpFlows {
		f.close()
	}
	s.log.Info("session closed", "frames_in", s.stats.FramesIn,
		"frames_out", s.stats.FramesOut, "tcp_flows", s.stats.TCPFlows,
		"udp_flows", s.stats.UDPFlows, "icmp_dropped", s.stats.ICMPDropped)
}

// ---------------------------------------------------------------------------
// Frame ingest
// ---------------------------------------------------------------------------

func (s *Session) handleFrame(in inbound) {
	f := in.frame
	s.stats.FramesIn++
	in.leg.lastRx = in.at

	switch f.Type {
	case icg.TypeHandshake:
		s.handleHandshake(in)
	case icg.TypeTCPUp:
		s.handleTCPUp(in)
	case icg.TypeUDP:
		s.handleUDPUp(in)
	case icg.TypeICMP:
		// Tunnelled ICMP needs a raw socket or a tun device to relay; see
		// the note on Config.ICMP. Counted rather than silently ignored.
		s.stats.ICMPDropped++
		if s.stats.ICMPDropped == 1 {
			s.log.Warn("dropping tunnelled ICMP: relaying it is not implemented")
		}
	case icg.TypeAck:
		s.handleAck(in)
	case icg.TypeSeqSync:
		s.handleSeqSync(in)
	default:
		s.stats.UnknownFrames++
		s.log.Debug("unknown frame type", "type", f.Type, "opcode", f.Opcode)
	}
}

// ---------------------------------------------------------------------------
// Handshake — ICG_WIRE_PROTOCOL.md §4, §6
// ---------------------------------------------------------------------------

func (s *Session) handleHandshake(in inbound) {
	f := in.frame
	switch f.Opcode {
	case icg.HSReqWithConfig:
		s.onHandshakeReq(in)

	case icg.HSConfirmAck:
		// The client only sends this after it has accepted our
		// ICG_SERVER_HANDSHAKE_ACK, and it moves itself to
		// ICG_AND_SRV_BOTH_OK on success. Mirror that.
		if s.state != icg.StateBothOK {
			s.state = icg.StateBothOK
			s.log.Info("handshake complete", "state", s.state)
		}
		s.noteTunnelID(in)

	case icg.HSKeepalive:
		s.noteTunnelID(in)
		// Answer liveness with a tunnel-detect probe, which is what ZTE's own
		// concentrator does (§6).
		s.sendOn(in.leg, &icg.Frame{Type: icg.TypeAck, Opcode: icg.AckTunnelDetect})

	case icg.HSRTTSync:
		s.onRTTSync(in)

	case icg.HSRTTAck:
		// The client echoes our SYNC_ACK back verbatim, so the server
		// timestamp in it is ours — which gives us a free RTT measurement for
		// this leg, and that is what we schedule downlink traffic on.
		if r, err := icg.ParseRTTBody(f.Body); err == nil && r.ServerMS != 0 {
			if rtt := in.at.Sub(time.UnixMilli(int64(r.ServerMS))); rtt > 0 && rtt < 10*time.Second {
				in.leg.observeRTT(rtt)
			}
		}

	case icg.HSServerAck:
		s.log.Warn("client sent ICG_SERVER_HANDSHAKE_ACK, which is a server-to-client opcode")

	default:
		s.stats.UnknownFrames++
		s.log.Debug("unhandled handshake opcode", "opcode", f.Opcode)
	}
}

func (s *Session) onHandshakeReq(in inbound) {
	s.stats.Handshakes++
	req, err := icg.ParseHandshakeReq(in.frame.Body)
	if err == nil {
		s.clientMAC, s.clientTunIP = req.MAC, req.IcgID
	} else {
		s.log.Warn("malformed handshake request", "err", err)
	}

	if !s.checkAdmission(err) {
		// Say nothing at all. The device retries once a second and will keep
		// retrying; staying silent is both the correct protocol response (it
		// simply never reaches ICG_SERVER_READY) and the quietest thing to do
		// to an internet scanner.
		return
	}

	// The client resets both sort modules and its send stash when it accepts
	// our ack (refresh_icg_resource), so we must reset ours in lockstep or we
	// would carry a stale sequence position into the new session.
	s.resetForHandshake()
	s.state = icg.StateSrvReady

	// The client never inspects the body of ICG_SERVER_HANDSHAKE_ACK — only
	// the opcode matters (§6) — so an empty body is correct and complete.
	s.sendOn(in.leg, &icg.Frame{Type: icg.TypeHandshake, Opcode: icg.HSServerAck})

	s.log.Info("handshake request answered",
		"mac", macString(s.clientMAC), "client_tun_ip", s.clientTunIP,
		"leg", in.leg.Key.id, "state", s.state)
}

// checkAdmission enforces Config.AllowedDevices. parseErr is the handshake
// parse error, if any: a body we could not read cannot be admitted when an
// allowlist is in force, because there is no identity in it to check.
func (s *Session) checkAdmission(parseErr error) bool {
	allow := s.srv.cfg.AllowedDevices
	if len(allow) == 0 {
		s.admitted = true
		return true
	}
	if parseErr != nil {
		s.refuse("unreadable handshake body while an allowlist is in force")
		return false
	}
	key := strings.ToLower(s.clientMAC.String())
	if !allow[key] {
		s.refuse("device " + key + " is not in the allowlist")
		return false
	}
	if !s.admitted {
		s.log.Info("device admitted", "mac", key)
	}
	s.admitted = true
	return true
}

func (s *Session) refuse(reason string) {
	s.admitted = false
	s.stats.Refused++
	// notice() collapses repeats, so a device stuck in its 1 Hz retry loop
	// shows up as one entry with a count rather than flooding the list.
	fix := "add the MAC to -devices if this is your CPE, otherwise ignore it"
	if len(s.clientMAC) > 0 {
		fix = "if this is your CPE, restart icgd with -devices " + strings.ToLower(s.clientMAC.String())
	}
	s.srv.notice(s.log, "warn", "device-refused", s.peerHint(), fix, "%s", reason)
}

// peerHint reports where the refused frames came from. The tun IP in the
// header is attacker-controlled, so it is useless for this.
func (s *Session) peerHint() string {
	for _, l := range s.legs {
		if l.Remote != nil {
			return l.Remote.String()
		}
	}
	return "unknown"
}

func (s *Session) resetForHandshake() {
	s.upTCP.Reset()
	s.upUDP.Reset()
	s.stashTCP = newStash(s.srv.cfg.StashLimit)
	s.stashUDP = newStash(s.srv.cfg.StashLimit)
	s.downTCPSeq = 0
	s.downUDPSeq = 0
	for _, f := range s.flows {
		f.close()
	}
	s.flows = make(map[icg.Flow]*tcpFlow)
	for _, f := range s.udpFlows {
		f.close()
	}
	s.udpFlows = make(map[udpKey]*udpFlow)
}

func (s *Session) onRTTSync(in inbound) {
	r, err := icg.ParseRTTBody(in.frame.Body)
	if err != nil {
		s.log.Debug("bad RTT sync body", "err", err)
		return
	}
	// Reply must echo the client's timestamp EXACTLY: the client computes its
	// RTT as its_own_now minus that value (§4.3). Everything else — seq, the
	// trailer — is echoed too.
	reply := r.Reply(in.at)
	s.sendOn(in.leg, &icg.Frame{
		Type:   icg.TypeHandshake,
		Opcode: icg.HSRTTSyncAck,
		Body:   reply.AppendTo(nil),
	})
}

// noteTunnelID learns which WAN leg a TCP tunnel is, from the tunnel id the
// client hides in the fake ping its keepalives carry (§4.2).
func (s *Session) noteTunnelID(in inbound) {
	if in.leg.TunnelID >= 0 {
		return
	}
	if id, ok := icg.TunnelIDFromFakePing(in.frame.Body); ok {
		in.leg.TunnelID = id
		s.log.Debug("leg identified", "leg", in.leg.Key.id, "tunnel_id", id)
	}
}

// ---------------------------------------------------------------------------
// ACKs and retransmission — §5
// ---------------------------------------------------------------------------

func (s *Session) handleAck(in inbound) {
	f := in.frame
	switch f.Opcode {
	case icg.AckTCPCumulative:
		s.stashTCP.ackUpTo(f.Seq)
	case icg.AckUDPCumulative:
		s.stashUDP.ackUpTo(f.Seq)

	case icg.AckTCPRetranRange:
		s.serveRetransmit(in.leg, s.stashTCP, f.Body)
	case icg.AckUDPRetranRange:
		s.serveRetransmit(in.leg, s.stashUDP, f.Body)

	case icg.AckTCPRetranOne:
		s.resendOne(in.leg, s.stashTCP, f.Seq)
	case icg.AckUDPRetranOne:
		s.resendOne(in.leg, s.stashUDP, f.Seq)

	case icg.AckTunnelDetect:
		// Liveness from the client's side; nothing to do.

	case icg.AckReportConfig, icg.AckReportPriority, icg.AckReportStatus, icg.AckReportSpeed:
		// Device telemetry. The body layouts are not mapped
		// (ICG_WIRE_PROTOCOL.md §12), so log the shape and move on.
		s.log.Debug("device telemetry", "report", icg.OpcodeName(f.Type, f.Opcode),
			"bytes", len(f.Body))

	default:
		s.stats.UnknownFrames++
		s.log.Debug("unhandled ack opcode", "opcode", f.Opcode, "bytes", len(f.Body))
	}
}

func (s *Session) serveRetransmit(leg *Leg, st *stash, body []byte) {
	seqs, err := icg.ParseSeqList(body)
	if err != nil {
		s.log.Debug("bad retransmit request", "err", err)
		return
	}
	for _, q := range seqs {
		s.resendOne(leg, st, q)
	}
}

func (s *Session) resendOne(leg *Leg, st *stash, seq uint32) {
	frame, ok := st.get(seq)
	if !ok {
		// Nothing we can do: the peer will eventually skip it, exactly as we
		// do in Reorder.Expire.
		return
	}
	s.stats.RetransmitsServed++
	// Retransmit on the leg that asked, not the scheduler's choice: that leg
	// is demonstrably alive and it is the one with the gap.
	leg.writeRaw(frame)
}

// ---------------------------------------------------------------------------
// Sequence resynchronisation — §9
// ---------------------------------------------------------------------------

func (s *Session) handleSeqSync(in inbound) {
	switch in.frame.Opcode {
	case icg.SyncTCPRequest:
		seq, _ := s.upTCP.Ack()
		s.sendOn(in.leg, &icg.Frame{Type: icg.TypeSeqSync, Opcode: icg.SyncTCPAck, Seq: seq})
	case icg.SyncUDPRequest:
		seq, _ := s.upUDP.Ack()
		s.sendOn(in.leg, &icg.Frame{Type: icg.TypeSeqSync, Opcode: icg.SyncUDPAck, Seq: seq})
	case icg.SyncTCPAck, icg.SyncUDPAck:
		// The client discards these too; nothing depends on them.
	default:
		s.log.Debug("unhandled seq-sync opcode", "opcode", in.frame.Opcode)
	}
}

// ---------------------------------------------------------------------------
// Periodic work
// ---------------------------------------------------------------------------

func (s *Session) tick(now time.Time) {
	// Ask for gaps, then give up on the ones that never arrive.
	if missing := s.upTCP.Missing(now, icg.SeqListMax); len(missing) > 0 {
		s.stats.RetransmitsRequested += uint64(len(missing))
		s.requestRetransmit(icg.AckTCPRetranRange, missing)
	}
	if missing := s.upUDP.Missing(now, icg.SeqListMax); len(missing) > 0 {
		s.stats.RetransmitsRequested += uint64(len(missing))
		s.requestRetransmit(icg.AckUDPRetranRange, missing)
	}
	for _, c := range s.upTCP.Expire(now) {
		s.deliverTCP(c)
	}
	for _, p := range s.upUDP.Expire(now) {
		s.deliverUDP(p)
	}

	// Cumulative ACKs, so the client can free its send stash.
	if now.Sub(s.lastTCPAck) >= s.srv.cfg.AckInterval {
		if seq, ok := s.upTCP.Ack(); ok {
			s.lastTCPAck = now
			s.sendOn(s.pickLeg("tcp"), &icg.Frame{Type: icg.TypeAck, Opcode: icg.AckTCPCumulative, Seq: seq})
		}
	}
	if now.Sub(s.lastUDPAck) >= s.srv.cfg.AckInterval {
		if seq, ok := s.upUDP.Ack(); ok {
			s.lastUDPAck = now
			s.sendOn(s.pickLeg("udp"), &icg.Frame{Type: icg.TypeAck, Opcode: icg.AckUDPCumulative, Seq: seq})
		}
	}

	if s.srv.cfg.StatsInterval > 0 && now.Sub(s.lastStats) >= s.srv.cfg.StatsInterval {
		s.lastStats = now
		s.logStats()
	}

	// Publish for the API. Twice a second is fresher than any UI needs and
	// cheap enough not to think about.
	if now.Sub(s.lastPublish) >= 500*time.Millisecond {
		s.lastPublish = now
		s.publish(now)
	}

	// Our own liveness. The client's zombie check gives us 30 s; 1 Hz per leg
	// matches what ZTE's concentrator was observed doing.
	if now.Sub(s.lastKeepalive) >= s.srv.cfg.KeepaliveInterval {
		s.lastKeepalive = now
		for _, leg := range s.legs {
			s.sendOn(leg, &icg.Frame{Type: icg.TypeAck, Opcode: icg.AckTunnelDetect})
		}
	}

	s.reapFlows(now)
}

func (s *Session) requestRetransmit(opcode uint8, seqs []uint32) {
	kind := "tcp"
	if opcode == icg.AckUDPRetranRange {
		kind = "udp"
	}
	f := &icg.Frame{Type: icg.TypeAck, Opcode: opcode, Seq: seqs[0]}
	f.Body = icg.AppendSeqList(nil, seqs)
	s.sendOn(s.pickLeg(kind), f)
}

// logStats surfaces the counters. Without this the reassembler's skip and
// retransmit numbers are invisible, and a concentrator that quietly drops data
// looks identical to one that works.
func (s *Session) logStats() {
	legs := make([]string, 0, len(s.legs))
	for _, l := range s.legs {
		legs = append(legs, fmt.Sprintf("%s(id=%d,rtt=%s)", l.Key.id, l.TunnelID, l.rtt.Round(time.Millisecond)))
	}
	s.log.Info("session stats",
		"state", s.state,
		"legs", strings.Join(legs, " "),
		"handshakes", s.stats.Handshakes,
		"admitted", s.admitted,
		"refused", s.stats.Refused, "refused_frames", s.stats.RefusedFrames,
		"frames_in", s.stats.FramesIn, "frames_out", s.stats.FramesOut,
		"dropped_in", s.dropped.Load(), "leg_write_errs", s.legWriteErrs(),
		"tcp_flows", s.stats.TCPFlows, "tcp_active", len(s.flows),
		"udp_flows", s.stats.UDPFlows, "udp_active", len(s.udpFlows),
		"icmp_dropped", s.stats.ICMPDropped,
		"tcp_up_pending", s.upTCP.Pending(), "tcp_up_skipped", s.upTCP.Skipped,
		"tcp_up_late", s.upTCP.Late,
		"udp_up_pending", s.upUDP.Pending(), "udp_up_skipped", s.upUDP.Skipped,
		"retrans_served", s.stats.RetransmitsServed,
		"retrans_requested", s.stats.RetransmitsRequested,
		"stash_tcp", s.stashTCP.len(),
		"stash_hits", s.stashTCP.Hits+s.stashUDP.Hits,
		"stash_misses", s.stashTCP.Misses+s.stashUDP.Misses,
		"unknown_frames", s.stats.UnknownFrames)
}

func (s *Session) legWriteErrs() uint64 {
	var n uint64
	for _, l := range s.legs {
		n += l.writeErrs.Load()
	}
	return n
}

func (s *Session) reapFlows(now time.Time) {
	for k, f := range s.udpFlows {
		if now.Sub(f.lastUse) > s.srv.cfg.UDPFlowIdle {
			f.close()
			delete(s.udpFlows, k)
		}
	}
}

// ---------------------------------------------------------------------------
// Leg management and egress
// ---------------------------------------------------------------------------

// pickLeg chooses where to put the next downlink packet. ICG stripes
// per-packet, and the client's own send-side model is lowest-RTT-first
// (TcpTunnelSelectModel=2), so we do the same with the RTT we learn from the
// RTT-ack echo. Legs with no measurement yet are used, but ranked last, so a
// fresh leg still gets traffic and thus a measurement.
//
// TCP legs are preferred for TCP data and UDP legs for UDP data, because that
// is what the client expects to demultiplex; kind == "" means "no preference".
func (s *Session) pickLeg(kind string) *Leg {
	var best *Leg
	for _, l := range s.legs {
		if l.closed.Load() {
			continue
		}
		if kind != "" && l.Kind != kind {
			continue
		}
		if best == nil || l.betterThan(best) {
			best = l
		}
	}
	if best == nil && kind != "" {
		// No leg of the requested kind: better to deliver over the wrong
		// transport than to drop, since the framing is identical.
		return s.pickLeg("")
	}
	return best
}

// sendOn writes a frame to a specific leg, filling in the session's identity.
func (s *Session) sendOn(leg *Leg, f *icg.Frame) {
	if leg == nil {
		return
	}
	f.Magic = s.srv.cfg.Magic
	f.IcgID = s.tunIP
	s.stats.FramesOut++
	leg.writeRaw(f.Encode())
}

// ---------------------------------------------------------------------------

func icgIDString(v uint32) string {
	var b [4]byte
	// The client writes this field in network order; render it that way.
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return netip.AddrFrom4(b).String()
}

func macString(m net.HardwareAddr) string {
	if len(m) == 0 {
		return "unknown"
	}
	return m.String()
}

// Leg is one transport path to the CPE — one WAN. A CPE opens a TCP connection
// per WAN and a UDP flow per WAN, all carrying the same tun_ip.
type Leg struct {
	Key      legKey
	Kind     string // "tcp" | "udp"
	Remote   net.Addr
	TunnelID int // from the keepalive fake-ping TLV; -1 until learned

	write func([]byte) error

	// lastRx and rtt belong to the session goroutine. closed is set by the
	// transport goroutine when the leg goes away, and read by the session
	// goroutine's scheduler, so it is atomic.
	lastRx time.Time
	rtt    time.Duration // smoothed, from the RTT-ack echo

	closed    atomic.Bool
	writeErrs atomic.Uint64
}

// Close marks the leg unusable. Safe from any goroutine.
func (l *Leg) Close() { l.closed.Store(true) }

func (l *Leg) writeRaw(b []byte) {
	if l.closed.Load() || l.write == nil {
		return
	}
	if err := l.write(b); err != nil {
		l.writeErrs.Add(1)
	}
}

func (l *Leg) observeRTT(sample time.Duration) {
	if l.rtt == 0 {
		l.rtt = sample
		return
	}
	// Same shape as a TCP SRTT: 7/8 old, 1/8 new.
	l.rtt = (l.rtt*7 + sample) / 8
}

// betterThan ranks legs for the send scheduler: measured beats unmeasured,
// lower RTT beats higher, and a recent packet breaks a tie.
func (l *Leg) betterThan(other *Leg) bool {
	switch {
	case l.rtt != 0 && other.rtt == 0:
		return true
	case l.rtt == 0 && other.rtt != 0:
		return false
	case l.rtt != other.rtt && l.rtt != 0:
		return l.rtt < other.rtt
	default:
		return l.lastRx.After(other.lastRx)
	}
}

type legKey struct {
	kind string
	id   string
}
