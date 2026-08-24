// Package concentrator implements the server side of ZTE's ICG multi-WAN
// bonding protocol: the "aggregation server" a ZTE CPE's zte_icg_agg data
// plane connects to.
//
// It exists so a CPE can bond its WANs through infrastructure we control
// rather than ZTE's cloud in mainland China. The protocol was
// reverse-engineered; docs/PROTOCOL.md is the
// specification and this package cites its section numbers throughout. What is
// proven versus guessed is documented there — read §12 before trusting an edge
// case.
//
// Shape of a session:
//
//	CPE                                    concentrator
//	 WAN0 --- TCP ---> :10088 ------\
//	 WAN1 --- TCP ---> :10088 -------> Session (keyed by icg_id)
//	 WAN0 --- UDP ---> :10000 ------/     |
//	 WAN1 --- UDP ---> :10001 -----/      +-- global TCP seq space (reassembled)
//	                                      +-- global UDP seq space (reassembled)
//	                                      +-- TCP proxy: one socket per 5-tuple
//	                                      +-- UDP NAT:   one socket per tuple pair
//
// There is no cryptography in this protocol and no authentication beyond a
// 4-byte magic that is a configuration constant. Do not expose a concentrator
// to the open internet without something else in front of it.
package concentrator

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/iangcarroll/zte-coord/icg"
)

// Config configures a Server. Zero values are filled in with defaults that
// match what was observed on the wire.
type Config struct {
	// TCPAddr is the tunnel listener, e.g. ":10088". The client takes the port
	// from icg.conf AggregationServerTcpPort (or from the MQTT dispatch, which
	// handed out 10039 in the observed session).
	TCPAddr string

	// UDPBase is the first UDP tunnel port; leg N connects to UDPBase+N. This
	// is icg.conf AggregationServerUdpStartPort. UDPLegs is how many to open.
	UDPBase int
	UDPLegs int

	// Magic must equal the client's icg.conf TunnelIdentifier, which is parsed
	// as hex. Zero means icg.DefaultMagic (0x12345678).
	Magic uint32

	// KeepaliveInterval is how often we send a tunnel-detect probe on each
	// leg. The client tears the session down after 30 s of silence and stops
	// its daemon after 150 s (§6), so this must stay well under 30 s.
	KeepaliveInterval time.Duration

	// AckInterval is how often we advertise a cumulative ACK per sequence
	// space. ZTE's server ACKed roughly every 100 packets.
	AckInterval time.Duration

	// Reorder tunes the reassemblers.
	Reorder ReorderConfig

	// StashLimit is how many sent frames per sequence space we keep for
	// retransmission.
	StashLimit int

	// MaxFlowsPerSession bounds proxied TCP connections and UDP NAT entries.
	MaxFlowsPerSession int

	// UDPFlowIdle is how long an unused UDP NAT entry survives.
	UDPFlowIdle time.Duration

	// SessionIdle is how long a session with no inbound frames survives.
	SessionIdle time.Duration

	// StatsInterval is how often each session logs its counters. Zero means
	// the default; negative disables it.
	StatsInterval time.Duration

	// Version is reported by the observability API. Cosmetic.
	Version string

	// AllowedDevices, when non-empty, restricts which CPEs may open a session:
	// a handshake whose MAC is not listed is refused and the session is never
	// admitted. Keys are lower-case colon-separated MACs.
	//
	// This is admission control, NOT authentication. The MAC arrives in a
	// plaintext, unsigned handshake over a protocol with no cryptography, so
	// anyone who knows a valid MAC can present it. What it buys is that
	// internet background noise and misconfigured devices cannot open a
	// session and use the box as a proxy, which for an exposed concentrator is
	// the difference that matters.
	AllowedDevices map[string]bool

	// DialContextTCP dials upstream on behalf of a proxied LAN connection.
	// Override it to restrict egress; the default is a plain dialer, which
	// means the concentrator will connect anywhere its clients ask it to.
	DialContextTCP func(ctx context.Context, network, addr string) (net.Conn, error)

	Logger *slog.Logger
}

func (c *Config) setDefaults() {
	if c.TCPAddr == "" {
		c.TCPAddr = ":10088"
	}
	if c.UDPBase == 0 {
		c.UDPBase = 10000
	}
	if c.UDPLegs == 0 {
		c.UDPLegs = 4
	}
	if c.Magic == 0 {
		c.Magic = icg.DefaultMagic
	}
	if c.KeepaliveInterval == 0 {
		c.KeepaliveInterval = time.Second
	}
	if c.AckInterval == 0 {
		c.AckInterval = 200 * time.Millisecond
	}
	if c.StashLimit == 0 {
		c.StashLimit = 8192
	}
	if c.MaxFlowsPerSession == 0 {
		c.MaxFlowsPerSession = 4096
	}
	if c.UDPFlowIdle == 0 {
		c.UDPFlowIdle = 60 * time.Second
	}
	if c.SessionIdle == 0 {
		c.SessionIdle = 5 * time.Minute
	}
	switch {
	case c.StatsInterval == 0:
		c.StatsInterval = 30 * time.Second
	case c.StatsInterval < 0:
		c.StatsInterval = 0
	}
	if c.DialContextTCP == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		c.DialContextTCP = d.DialContext
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// Server accepts ICG tunnels and multiplexes them into Sessions.
type Server struct {
	cfg Config
	log *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	sessions map[uint32]*Session

	wg sync.WaitGroup

	// Listeners, retained so TCPAddr/UDPAddrs can report what we actually
	// bound (useful when the caller asks for :0). Guarded by mu because they
	// are written by Run and read by callers on other goroutines.
	tcpLn   net.Listener
	udpConn []*net.UDPConn

	// ready is closed once the listeners are bound, so a caller can wait
	// rather than poll.
	ready     chan struct{}
	readyOnce sync.Once

	// badPeers remembers which UDP peers we have already complained about, so
	// an exposed listener cannot be turned into a log flood. Guarded by mu.
	badPeers map[string]bool

	notices   noticeLog
	startedAt time.Time
	version   string
}

// New validates the configuration. Nothing is bound until Run.
func New(cfg Config) *Server {
	cfg.setDefaults()
	return &Server{
		cfg:       cfg,
		log:       cfg.Logger.With("component", "icg-concentrator"),
		sessions:  make(map[uint32]*Session),
		ready:     make(chan struct{}),
		startedAt: time.Now(),
		version:   cfg.Version,
	}
}

// Run binds the listeners and serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()

	ln, err := net.Listen("tcp", s.cfg.TCPAddr)
	if err != nil {
		return fmt.Errorf("icg: listen tcp %s: %w", s.cfg.TCPAddr, err)
	}
	udp := make([]*net.UDPConn, 0, s.cfg.UDPLegs)
	for i := 0; i < s.cfg.UDPLegs; i++ {
		port := s.cfg.UDPBase + i
		if s.cfg.UDPBase == 0 {
			port = 0 // let the kernel pick, one ephemeral port per leg
		}
		uc, uerr := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
		if uerr != nil {
			_ = ln.Close()
			for _, c := range udp {
				_ = c.Close()
			}
			return fmt.Errorf("icg: listen udp :%d: %w", port, uerr)
		}
		udp = append(udp, uc)
	}

	s.mu.Lock()
	s.tcpLn, s.udpConn = ln, udp
	s.mu.Unlock()
	s.readyOnce.Do(func() { close(s.ready) })

	s.log.Info("concentrator listening",
		"tcp", ln.Addr().String(),
		"udp_base", s.cfg.UDPBase, "udp_legs", s.cfg.UDPLegs,
		"magic", fmt.Sprintf("%#x", s.cfg.Magic))

	// Shut the listeners when the context goes, so the accept loops unblock.
	go func() {
		<-s.ctx.Done()
		s.closeListeners()
	}()

	for i, uc := range udp {
		s.wg.Add(1)
		go func(idx int, uc *net.UDPConn) {
			defer s.wg.Done()
			s.serveUDP(idx, uc)
		}(i, uc)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.reapSessions()
	}()

	err = s.acceptTCP(ln)
	s.cancel()
	s.wg.Wait()
	if errors.Is(err, net.ErrClosed) && s.ctx.Err() != nil {
		return nil // ordinary shutdown
	}
	return err
}

// Ready is closed once the listeners are bound. Useful when TCPAddr was
// configured with port 0.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// TCPAddr reports the bound TCP address, or nil before Run has bound it.
func (s *Server) TCPAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcpLn == nil {
		return nil
	}
	return s.tcpLn.Addr()
}

// UDPAddrs reports the bound UDP addresses, in leg order.
func (s *Server) UDPAddrs() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]net.Addr, 0, len(s.udpConn))
	for _, uc := range s.udpConn {
		out = append(out, uc.LocalAddr())
	}
	return out
}

func (s *Server) closeListeners() {
	s.mu.Lock()
	ln, udp := s.tcpLn, s.udpConn
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for _, uc := range udp {
		_ = uc.Close()
	}
}

func (s *Server) acceptTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveTCPConn(conn)
		}()
	}
}

// serveTCPConn deframes one WAN leg's TCP tunnel.
//
// A leg belongs to a session, but we do not know which until the first frame
// arrives and tells us its icg_id — so the leg is registered lazily and moved
// nowhere afterwards. A CPE with three WANs produces three of these.
func (s *Server) serveTCPConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	log := s.log.With("leg", "tcp:"+remote.String())
	log.Info("tunnel leg connected")

	// A leg that says nothing is a leg that is gone. The client keepalives at
	// ~1 Hz per tunnel, so this is generous.
	const readTimeout = 90 * time.Second

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true) // per-packet bonding: latency beats coalescing
	}

	leg := &Leg{
		Key:      legKey{kind: "tcp", id: remote.String()},
		Kind:     "tcp",
		Remote:   remote,
		TunnelID: -1,
	}
	var writeMu sync.Mutex
	leg.write = func(b []byte) error {
		// Frames must not interleave on a stream, and several goroutines can
		// write to a leg (the session plus retransmit paths).
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err := conn.Write(b)
		return err
	}

	sr := icg.NewStreamReader(conn, s.cfg.Magic)
	// A magic mismatch is the single most likely misconfiguration, and the
	// device will not tell its operator anything useful about it. Say exactly
	// what we saw and exactly which knob fixes it.
	sr.OnDesync = func(prefix []byte) {
		if len(prefix) >= 4 {
			if got := binary.LittleEndian.Uint32(prefix); got != s.cfg.Magic {
				s.notice(log, "warn", "magic-mismatch", remote.String(),
					fmt.Sprintf("set icg.conf TunnelIdentifier=%x on the device, or restart icgd with -magic %x",
						s.cfg.Magic, got),
					"wrong TunnelIdentifier: the peer sent magic %s, we expect %s",
					hex32(got), hex32(s.cfg.Magic))
				return
			}
		}
		s.notice(log, "warn", "framing-lost", remote.String(),
			"check the peer really is zte_icg_agg and that nothing is rewriting the stream",
			"lost frame framing; the magic matched but the length did not (saw % x)", prefix)
	}

	var sess *Session
	defer func() {
		leg.Close()
		if sess != nil {
			sess.detachLeg(leg.Key)
		}
		if sess == nil {
			// A leg that connects and never sends a valid frame is the
			// signature of a port scan, or of a device that cannot agree on
			// the framing. Either way the operator wants to know.
			s.notice(log, "warn", "no-valid-frame", remote.String(),
				"check the device is using this port and this TunnelIdentifier",
				"a peer connected and disconnected without ever sending a valid ICG frame (%d resyncs)",
				sr.Resyncs)
		} else {
			log.Info("tunnel leg disconnected", "resyncs", sr.Resyncs)
		}
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		f, err := sr.Next()
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				log.Info("leg read ended", "err", err, "resyncs", sr.Resyncs)
			}
			return
		}
		if sess == nil {
			sess = s.session(f.IcgID)
			sess.attachLeg(leg)
			log = log.With("icg_id", icgIDString(f.IcgID))
			log.Info("leg bound to session")
		}
		sess.post(f, leg)
	}
}

// serveUDP handles one UDP tunnel port. Unlike TCP, a UDP leg has no
// connection: the peer address can change (NAT rebinding on a cellular WAN is
// routine), so the leg is re-pointed at whatever address last spoke to us on
// this port.
func (s *Server) serveUDP(idx int, uc *net.UDPConn) {
	log := s.log.With("leg", fmt.Sprintf("udp:%d", idx))
	buf := make([]byte, 65535)

	type peerLeg struct {
		leg  *Leg
		sess *Session
	}
	// A cellular WAN re-NATs routinely, so a leg's source address changes over
	// a session's life. Bound the table so a peer that rebinds constantly (or
	// a spoofer) cannot grow it without limit.
	const maxPeers = 64
	peers := make(map[string]*peerLeg)

	for {
		n, addr, err := uc.ReadFromUDP(buf)
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				log.Info("udp leg read ended", "err", err)
			}
			return
		}
		// A UDP datagram may hold several frames, same as a TCP segment.
		for off := 0; off < n; {
			f, used, derr := icg.Decode(buf[off:n], s.cfg.Magic)
			if derr != nil {
				if off == 0 {
					s.reportBadDatagram(log, addr, buf[:n], derr)
				}
				break
			}
			off += used

			key := addr.String()
			pl := peers[key]
			if pl == nil {
				if len(peers) >= maxPeers {
					// Drop the whole table rather than pick a victim: the
					// legs re-register on their next datagram, and the
					// sessions they belong to are unaffected.
					log.Warn("udp peer table full, resetting", "peers", len(peers))
					for _, old := range peers {
						old.leg.Close()
						old.sess.detachLeg(old.leg.Key)
					}
					peers = make(map[string]*peerLeg)
				}
				dst := addr // capture per peer
				leg := &Leg{
					Key:      legKey{kind: "udp", id: fmt.Sprintf("%d/%s", idx, key)},
					Kind:     "udp",
					Remote:   dst,
					TunnelID: idx,
				}
				leg.write = func(b []byte) error {
					_, werr := uc.WriteToUDP(b, dst)
					return werr
				}
				sess := s.session(f.IcgID)
				sess.attachLeg(leg)
				pl = &peerLeg{leg: leg, sess: sess}
				peers[key] = pl
				log.Info("udp leg bound to session", "from", key,
					"icg_id", icgIDString(f.IcgID))
			}
			pl.sess.post(f, pl.leg)
		}
	}
}

// reportBadDatagram explains an unparseable UDP datagram once per peer. Same
// reasoning as OnDesync: the device will not surface this, so we must.
func (s *Server) reportBadDatagram(log *slog.Logger, addr *net.UDPAddr, b []byte, err error) {
	key := addr.String()
	s.mu.Lock()
	if s.badPeers == nil {
		s.badPeers = map[string]bool{}
	}
	first := !s.badPeers[key]
	if first && len(s.badPeers) < 256 {
		s.badPeers[key] = true
	}
	s.mu.Unlock()
	if !first {
		return
	}
	if len(b) >= 4 {
		if got := binary.LittleEndian.Uint32(b); got != s.cfg.Magic {
			s.notice(log, "warn", "magic-mismatch-udp", key,
				fmt.Sprintf("set icg.conf TunnelIdentifier=%x on the device, or restart icgd with -magic %x",
					s.cfg.Magic, got),
				"UDP datagram with the wrong TunnelIdentifier: peer sent %s, we expect %s",
				hex32(got), hex32(s.cfg.Magic))
			return
		}
	}
	s.notice(log, "warn", "bad-udp-datagram", key,
		"check nothing else is sending to this UDP port",
		"unparseable UDP datagram, %d bytes, head % x (%v)", len(b), b[:min(16, len(b))], err)
}

// session returns the session for an icg_id, creating and starting it if needed.
func (s *Server) session(tunIP uint32) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[tunIP]; ok {
		return sess
	}
	sess := newSession(s, tunIP)
	s.sessions[tunIP] = sess
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		sess.run(s.ctx)
	}()
	sess.log.Info("session created")
	return sess
}

// Sessions returns a snapshot of live sessions, for diagnostics.
func (s *Server) Sessions() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

func (s *Server) reapSessions() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			// Sessions are reaped by the server, but lastRx belongs to the
			// session goroutine, so ask rather than read.
			s.mu.Lock()
			for k, sess := range s.sessions {
				if sess.IdleFor() > s.cfg.SessionIdle {
					sess.log.Info("reaping idle session")
					sess.stop()
					delete(s.sessions, k)
				}
			}
			s.mu.Unlock()
		}
	}
}
