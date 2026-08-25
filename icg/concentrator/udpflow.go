package concentrator

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/iangcarroll/zte-concentrator/icg"
)

// The UDP path is a NAT, not a proxy. Tunnelled UDP arrives as a complete raw
// IPv4 packet whose source is inside the tun subnet (ICG_WIRE_PROTOCOL.md §8),
// so the concentrator has to do what a home router does: allocate an outbound
// socket per (inside tuple, outside tuple), rewrite, and translate the replies
// back.
//
// Using ordinary UDP sockets rather than a tun device keeps this portable and
// unprivileged. The cost is that we cannot relay anything that is not UDP —
// notably ICMP, including the ICMP errors that would tell an inside host its
// datagram was rejected.

// udpKey is the NAT table key: the inside tuple plus the outside tuple, so two
// LAN hosts talking to the same server from the same port still get their own
// socket.
type udpKey struct {
	inside  netip.AddrPort
	outside netip.AddrPort
}

type udpFlow struct {
	key     udpKey
	conn    *net.UDPConn
	lastUse time.Time
	closed  bool

	// ttl and ipID are copied from the first inside packet so that replies
	// look plausible to the inside host.
	ipID uint16
}

// handleUDPUp ingests a type-0 frame into the global UDP sequence space.
//
// UDP is sequenced by ICG even though UDP itself is unordered, because the
// point of the sequence space is tunnel reassembly across legs, not
// application ordering. We still respect it: delivering a reordered burst of
// DNS or QUIC out of order would be measurably worse than the small delay.
func (s *Session) handleUDPUp(in inbound) {
	pkt := append(make([]byte, 0, len(in.frame.Body)), in.frame.Body...)
	for _, ready := range s.upUDP.Push(in.frame.Seq, pkt, in.at) {
		s.deliverUDP(ready)
	}
}

func (s *Session) deliverUDP(pkt []byte) {
	ip, err := parseIPv4(pkt)
	if err != nil {
		s.log.Debug("bad tunnelled IPv4", "err", err, "bytes", len(pkt))
		return
	}
	if ip.Proto != protoUDP {
		// The client sends non-UDP over tun0 as type 1; anything else here is
		// unexpected.
		s.log.Debug("type-0 frame carried IP proto", "proto", ip.Proto)
		return
	}
	d, err := parseUDP(ip)
	if err != nil {
		s.log.Debug("bad tunnelled UDP", "err", err)
		return
	}

	key := udpKey{inside: d.Src, outside: d.Dst}
	f := s.udpFlows[key]
	if f == nil {
		if len(s.udpFlows) >= s.srv.cfg.MaxFlowsPerSession {
			s.log.Warn("refusing new UDP flow: per-session limit reached",
				"limit", s.srv.cfg.MaxFlowsPerSession)
			return
		}
		f = s.openUDPFlow(key, ip.ID)
		if f == nil {
			return
		}
	}
	f.lastUse = time.Now()
	if _, err := f.conn.Write(d.Data); err != nil {
		s.log.Debug("upstream UDP write failed", "flow", key.outside, "err", err)
	}
}

func (s *Session) openUDPFlow(key udpKey, ipID uint16) *udpFlow {
	raddr := net.UDPAddrFromAddrPort(key.outside)
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		s.log.Debug("upstream UDP dial failed", "dst", key.outside, "err", err)
		return nil
	}
	f := &udpFlow{key: key, conn: conn, lastUse: time.Now(), ipID: ipID}
	s.udpFlows[key] = f
	s.stats.UDPFlows++

	go s.udpReadPump(f)
	return f
}

// udpReadPump reads replies and re-encapsulates them as complete IPv4 packets
// addressed back to the inside host — the NAT's reverse translation.
func (s *Session) udpReadPump(f *udpFlow) {
	buf := make([]byte, 65535)
	for {
		n, err := f.conn.Read(buf)
		if n > 0 {
			f.ipID++
			pkt := buildUDPPacket(f.key.outside, f.key.inside, f.ipID, 64, buf[:n])
			s.postUpstream(upstreamData{udpPacket: pkt})
		}
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.log.Debug("upstream UDP read ended", "flow", f.key.outside, "err", err)
			}
			return
		}
	}
}

// sendUDPDown emits one type-0 frame carrying a whole IPv4 packet. Unlike TCP
// data, the sub-header seq really is the sequence number here (§2).
func (s *Session) sendUDPDown(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	seq := s.downUDPSeq
	s.downUDPSeq++

	f := &icg.Frame{Type: icg.TypeUDP, Opcode: 0, Seq: seq, Body: pkt}
	f.Magic = s.srv.cfg.Magic
	f.IcgID = s.tunIP

	enc := f.Encode()
	s.stashUDP.put(seq, enc)
	s.stats.FramesOut++

	if leg := s.pickLeg("udp"); leg != nil {
		leg.writeRaw(enc)
	}
}

func (f *udpFlow) close() {
	if f.closed {
		return
	}
	f.closed = true
	_ = f.conn.Close()
}
