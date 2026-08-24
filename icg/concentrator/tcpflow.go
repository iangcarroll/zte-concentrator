package concentrator

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/iangcarroll/zte-coord/icg"
)

// The TCP path is a transparent proxy. The client DNATs LAN TCP to the
// concentrator's tun address, recovers the real destination with
// SO_ORIGINAL_DST, and ships the original 5-tuple in every frame
// (ICG_WIRE_PROTOCOL.md §7). So we never see IP-level TCP from the client at
// all: we see a stream of {seq, opcode, 5-tuple, bytes} records and are
// expected to maintain one upstream socket per tuple.
//
// maxChunk is how much stream data we put in one downlink frame. The client
// clamps TCP MSS to 1400 and reads at most 1400 bytes per frame on the way up,
// so matching that keeps frames inside one MTU on the WAN legs too.
const maxChunk = 1400

// tcpFlow is one proxied connection. Writes toward the upstream go through a
// queue so that a slow or blocked upstream socket can never stall the session
// goroutine, which also serves every other flow and all the control traffic.
type tcpFlow struct {
	flow icg.Flow

	writes chan []byte
	done   chan struct{} // closed exactly once, by close()
	once   sync.Once

	// conn is set by the dial goroutine and read by the write pump, so it is
	// guarded rather than plain. closed lets the dial goroutine notice that
	// the session tore the flow down while the SYN was still in flight.
	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

// handleTCPUp ingests an uplink TCP data frame into the global TCP sequence
// space. Ordering matters absolutely here — a byte stream reassembled out of
// order is corruption, not just latency — so nothing is acted on until the
// reassembler says it is next.
func (s *Session) handleTCPUp(in inbound) {
	body, err := icg.ParseTCPBody(in.frame.Body)
	if err != nil {
		s.log.Debug("bad TCP body", "err", err)
		return
	}
	// The frame's Body aliases the leg's read buffer, so copy anything we keep.
	c := tcpChunk{flow: body.UpFlow(), op: body.Opcode}
	if len(body.Data) > 0 {
		c.data = append(make([]byte, 0, len(body.Data)), body.Data...)
	}
	for _, ready := range s.upTCP.Push(body.Seq, c, in.at) {
		s.deliverTCP(ready)
	}
}

func (s *Session) deliverTCP(c tcpChunk) {
	switch c.op {
	case icg.TCPConnect:
		s.openFlow(c.flow)

	case icg.TCPPayload:
		f := s.flows[c.flow]
		if f == nil {
			// The client sends CONNECT first, but a retransmit-skip can lose
			// it. Opening lazily is strictly better than dropping the stream.
			f = s.openFlow(c.flow)
			if f == nil {
				return
			}
		}
		f.enqueue(c.data)

	case icg.TCPDisconnect:
		if f := s.flows[c.flow]; f != nil {
			f.close()
			delete(s.flows, c.flow)
		}

	case icg.TCPBlock, icg.TCPUnblock:
		// Flow control from the client's proxy_fd_monitor_proc. We do not
		// generate downlink fast enough for this to matter yet, and the
		// numbering is inferred rather than proven (§7), so log only.
		s.log.Debug("tcp flow control", "flow", c.flow, "opcode", c.op)

	default:
		s.log.Debug("unknown tcp opcode", "flow", c.flow, "opcode", c.op)
	}
}

// openFlow dials the original destination and starts pumping it back.
func (s *Session) openFlow(flow icg.Flow) *tcpFlow {
	if f, ok := s.flows[flow]; ok {
		return f
	}
	if len(s.flows) >= s.srv.cfg.MaxFlowsPerSession {
		s.log.Warn("refusing new flow: per-session limit reached",
			"limit", s.srv.cfg.MaxFlowsPerSession, "flow", flow)
		s.sendTCPDown(flow, icg.TCPDisconnect, nil)
		return nil
	}

	f := &tcpFlow{
		flow:   flow,
		writes: make(chan []byte, 64),
		done:   make(chan struct{}),
	}
	s.flows[flow] = f
	s.stats.TCPFlows++

	// Dial off the session goroutine: a SYN to an unreachable host takes
	// seconds and must not block the tunnel.
	go func() {
		conn, err := s.srv.cfg.DialContextTCP(s.srv.ctx, "tcp", flow.Server.String())
		if err != nil {
			// This is the failure that looks exactly like "the tunnel is
			// broken" from the device's side, so it must be visible without
			// -v: the device will report nothing at all.
			s.srv.notice(s.log, "warn", "upstream-dial-failed", flow.Server.String(),
				"check the concentrator's own egress: DNS the device resolved may "+
					"point somewhere this server cannot reach, and -allow/-deny gate it",
				"could not reach %s for LAN client %s: %v", flow.Server, flow.Client, err)
			s.postUpstream(upstreamData{isTCP: true, flow: flow, dialFailed: true, closed: true})
			f.close()
			return
		}
		// The client may have sent DISCONNECT while the SYN was in flight; if
		// so the flow is already gone and this socket must not be left open.
		if !f.adopt(conn) {
			_ = conn.Close()
			return
		}
		go f.writePump()
		s.readPump(f)
	}()
	return f
}

// readPump moves upstream bytes toward the client. It runs on its own
// goroutine and hands chunks to the session over the out channel, because only
// the session goroutine may allocate downlink sequence numbers.
func (s *Session) readPump(f *tcpFlow) {
	defer f.close()
	conn := f.socket()
	buf := make([]byte, maxChunk)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			s.postUpstream(upstreamData{
				isTCP: true,
				flow:  f.flow,
				data:  append(make([]byte, 0, n), buf[:n]...),
			})
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.log.Debug("upstream read ended", "flow", f.flow, "err", err)
			}
			s.postUpstream(upstreamData{isTCP: true, flow: f.flow, closed: true})
			return
		}
	}
}

func (s *Session) postUpstream(u upstreamData) {
	select {
	case s.out <- u:
	case <-s.srv.ctx.Done():
	}
}

// handleUpstream runs on the session goroutine: assign the next global downlink
// sequence number, frame it, stash it for retransmission, send it.
func (s *Session) handleUpstream(u upstreamData) {
	if !u.isTCP {
		s.sendUDPDown(u.udpPacket)
		return
	}
	if u.closed {
		if u.dialFailed {
			s.stats.UpstreamDialFails++
		}
		if f, ok := s.flows[u.flow]; ok {
			f.close()
			delete(s.flows, u.flow)
		}
		s.sendTCPDown(u.flow, icg.TCPDisconnect, nil)
		return
	}
	for off := 0; off < len(u.data); off += maxChunk {
		end := min(off+maxChunk, len(u.data))
		s.sendTCPDown(u.flow, icg.TCPPayload, u.data[off:end])
	}
}

// sendTCPDown emits one type-2 frame. The tuple is swapped relative to the
// uplink, which is what DownBody does.
func (s *Session) sendTCPDown(flow icg.Flow, op icg.TCPOpcode, data []byte) {
	seq := s.downTCPSeq
	s.downTCPSeq++

	f := &icg.Frame{
		Type:   icg.TypeTCPDown,
		Opcode: 0,
		// The sub-header seq on TCP data frames is a CRC32, not a sequence
		// number (§7). ZTE's own concentrator sends 0 here and the client
		// accepts it, so we do the same rather than computing a checksum the
		// client appears not to check.
		Seq:  0,
		Body: flow.DownBody(seq, op, data).AppendTo(nil),
	}
	f.Magic = s.srv.cfg.Magic
	f.TunIP = s.tunIP

	enc := f.Encode()
	s.stashTCP.put(seq, enc)
	s.stats.FramesOut++

	if leg := s.pickLeg("tcp"); leg != nil {
		leg.writeRaw(enc)
	}
}

// adopt attaches a freshly dialled socket, reporting false if the flow was
// closed in the meantime.
func (f *tcpFlow) adopt(c net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.conn = c
	return true
}

func (f *tcpFlow) socket() net.Conn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conn
}

func (f *tcpFlow) enqueue(b []byte) {
	if len(b) == 0 {
		return
	}
	select {
	case <-f.done:
		return
	default:
	}
	select {
	case f.writes <- b:
	case <-f.done:
	default:
		// The upstream socket is backed up harder than our queue. Dropping
		// here would silently corrupt the stream, so block briefly and give
		// up only if the flow is going away.
		select {
		case f.writes <- b:
		case <-f.done:
		case <-time.After(2 * time.Second):
		}
	}
}

func (f *tcpFlow) writePump() {
	conn := f.socket()
	if conn == nil {
		return
	}
	for {
		select {
		case b := <-f.writes:
			if _, err := conn.Write(b); err != nil {
				return
			}
		case <-f.done:
			// Flush what is already queued: the client sent it before the
			// close, so the upstream is entitled to see it.
			for {
				select {
				case b := <-f.writes:
					if _, err := conn.Write(b); err != nil {
						return
					}
				default:
					return
				}
			}
		}
	}
}

// close is idempotent and safe from any goroutine.
func (f *tcpFlow) close() {
	f.once.Do(func() {
		f.mu.Lock()
		f.closed = true
		conn := f.conn
		f.mu.Unlock()
		close(f.done)
		if conn != nil {
			_ = conn.Close()
		}
	})
}
