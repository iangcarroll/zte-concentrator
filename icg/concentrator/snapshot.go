package concentrator

import (
	"sort"
	"sync/atomic"
	"time"
)

// Observability is not a nicety for this protocol, it is a requirement.
// zte_icg_agg was written to talk to ZTE's own cloud and reports essentially
// nothing useful to its operator when pointed somewhere else: a wrong
// TunnelIdentifier, a refused device or an unreachable upstream all present as
// "the tunnel just doesn't work". So the concentrator has to be the place where
// the truth is visible.
//
// Snapshots are published by each session's own goroutine into an atomic
// pointer, which keeps the read path lock-free and keeps every other goroutine
// out of session state.

// ServerSnapshot is everything the API and UI need in one shot.
type ServerSnapshot struct {
	Version   string            `json:"version"`
	StartedAt time.Time         `json:"started_at"`
	UptimeSec float64           `json:"uptime_sec"`
	Listeners ListenerSnapshot  `json:"listeners"`
	Magic     string            `json:"magic"`
	Admission AdmissionSnapshot `json:"admission"`
	Sessions  []SessionSnapshot `json:"sessions"`
	Notices   []Notice          `json:"notices"`
}

// ListenerSnapshot reports what we are actually bound to, which is the first
// thing to check when a device cannot connect.
type ListenerSnapshot struct {
	TCP     string   `json:"tcp"`
	UDP     []string `json:"udp"`
	UDPBase int      `json:"udp_base"`
	UDPLegs int      `json:"udp_legs"`
}

// AdmissionSnapshot describes the device allowlist.
type AdmissionSnapshot struct {
	Enabled bool     `json:"enabled"`
	Devices []string `json:"devices"`
}

// SessionSnapshot is one CPE's state at a moment in time.
type SessionSnapshot struct {
	TunIP       string          `json:"tun_ip"`
	State       string          `json:"state"`
	Admitted    bool            `json:"admitted"`
	ClientMAC   string          `json:"client_mac"`
	ClientTunIP string          `json:"client_tun_ip"`
	CreatedAt   time.Time       `json:"created_at"`
	IdleSec     float64         `json:"idle_sec"`
	Legs        []LegSnapshot   `json:"legs"`
	Flows       FlowsSnapshot   `json:"flows"`
	Reassembly  ReasmSnapshot   `json:"reassembly"`
	Counters    CounterSnapshot `json:"counters"`
}

// LegSnapshot is one WAN path.
type LegSnapshot struct {
	Kind      string  `json:"kind"`
	Remote    string  `json:"remote"`
	TunnelID  int     `json:"tunnel_id"`
	RTTMillis float64 `json:"rtt_ms"`
	IdleSec   float64 `json:"idle_sec"`
	WriteErrs uint64  `json:"write_errors"`
	Closed    bool    `json:"closed"`
}

type FlowsSnapshot struct {
	TCPActive int    `json:"tcp_active"`
	TCPTotal  uint64 `json:"tcp_total"`
	UDPActive int    `json:"udp_active"`
	UDPTotal  uint64 `json:"udp_total"`
}

// ReasmSnapshot exposes the reorder buffers. Pending is normal and transient;
// Skipped means data was thrown away, which is the number that matters.
type ReasmSnapshot struct {
	TCPPending int    `json:"tcp_pending"`
	TCPSkipped uint64 `json:"tcp_skipped"`
	TCPLate    uint64 `json:"tcp_late"`
	UDPPending int    `json:"udp_pending"`
	UDPSkipped uint64 `json:"udp_skipped"`
	UDPLate    uint64 `json:"udp_late"`
	StashTCP   int    `json:"stash_tcp"`
	StashUDP   int    `json:"stash_udp"`
	StashMiss  uint64 `json:"stash_misses"`
}

type CounterSnapshot struct {
	FramesIn             uint64 `json:"frames_in"`
	FramesOut            uint64 `json:"frames_out"`
	DroppedIn            uint64 `json:"dropped_in"`
	Handshakes           uint64 `json:"handshakes"`
	Refused              uint64 `json:"refused"`
	RefusedFrames        uint64 `json:"refused_frames"`
	ICMPDropped          uint64 `json:"icmp_dropped"`
	RetransmitsServed    uint64 `json:"retransmits_served"`
	RetransmitsRequested uint64 `json:"retransmits_requested"`
	UnknownFrames        uint64 `json:"unknown_frames"`
	UpstreamDialFails    uint64 `json:"upstream_dial_failures"`
}

// snapshot builds the session's view. Session-goroutine only.
func (s *Session) snapshot(now time.Time) SessionSnapshot {
	out := SessionSnapshot{
		TunIP:     tunIPString(s.tunIP),
		State:     s.state.String(),
		Admitted:  s.admitted,
		ClientMAC: macString(s.clientMAC),
		CreatedAt: s.createdAt,
		Flows: FlowsSnapshot{
			TCPActive: len(s.flows), TCPTotal: s.stats.TCPFlows,
			UDPActive: len(s.udpFlows), UDPTotal: s.stats.UDPFlows,
		},
		Reassembly: ReasmSnapshot{
			TCPPending: s.upTCP.Pending(), TCPSkipped: s.upTCP.Skipped, TCPLate: s.upTCP.Late,
			UDPPending: s.upUDP.Pending(), UDPSkipped: s.upUDP.Skipped, UDPLate: s.upUDP.Late,
			StashTCP: s.stashTCP.len(), StashUDP: s.stashUDP.len(),
			StashMiss: s.stashTCP.Misses + s.stashUDP.Misses,
		},
		Counters: CounterSnapshot{
			FramesIn: s.stats.FramesIn, FramesOut: s.stats.FramesOut,
			DroppedIn:  s.dropped.Load(),
			Handshakes: s.stats.Handshakes,
			Refused:    s.stats.Refused, RefusedFrames: s.stats.RefusedFrames,
			ICMPDropped:          s.stats.ICMPDropped,
			RetransmitsServed:    s.stats.RetransmitsServed,
			RetransmitsRequested: s.stats.RetransmitsRequested,
			UnknownFrames:        s.stats.UnknownFrames,
			UpstreamDialFails:    s.stats.UpstreamDialFails,
		},
	}
	if s.clientTunIP.IsValid() {
		out.ClientTunIP = s.clientTunIP.String()
	}
	if ns := s.lastRxUnixNano.Load(); ns != 0 {
		out.IdleSec = now.Sub(time.Unix(0, ns)).Seconds()
	}
	for _, l := range s.legs {
		ls := LegSnapshot{
			Kind: l.Kind, TunnelID: l.TunnelID,
			RTTMillis: float64(l.rtt) / float64(time.Millisecond),
			WriteErrs: l.writeErrs.Load(), Closed: l.closed.Load(),
		}
		if l.Remote != nil {
			ls.Remote = l.Remote.String()
		}
		if !l.lastRx.IsZero() {
			ls.IdleSec = now.Sub(l.lastRx).Seconds()
		}
		out.Legs = append(out.Legs, ls)
	}
	sort.Slice(out.Legs, func(i, j int) bool {
		if out.Legs[i].Kind != out.Legs[j].Kind {
			return out.Legs[i].Kind < out.Legs[j].Kind
		}
		return out.Legs[i].Remote < out.Legs[j].Remote
	})
	return out
}

// publish makes the latest snapshot readable from other goroutines.
func (s *Session) publish(now time.Time) {
	snap := s.snapshot(now)
	s.pub.Store(&snap)
}

// Snapshot returns the last published view, or a placeholder if the session
// has not ticked yet.
func (s *Session) Snapshot() SessionSnapshot {
	if p := s.pub.Load(); p != nil {
		return *p
	}
	return SessionSnapshot{TunIP: tunIPString(s.tunIP), State: "starting"}
}

// Snapshot gathers the whole server's state.
func (s *Server) Snapshot() ServerSnapshot {
	now := time.Now()
	out := ServerSnapshot{
		Version:   s.version,
		StartedAt: s.startedAt,
		UptimeSec: now.Sub(s.startedAt).Seconds(),
		Magic:     hex32(s.cfg.Magic),
		Listeners: ListenerSnapshot{UDPBase: s.cfg.UDPBase, UDPLegs: s.cfg.UDPLegs},
		Notices:   s.Notices(),
	}
	if a := s.TCPAddr(); a != nil {
		out.Listeners.TCP = a.String()
	}
	for _, a := range s.UDPAddrs() {
		out.Listeners.UDP = append(out.Listeners.UDP, a.String())
	}
	if n := len(s.cfg.AllowedDevices); n > 0 {
		out.Admission.Enabled = true
		for mac := range s.cfg.AllowedDevices {
			out.Admission.Devices = append(out.Admission.Devices, mac)
		}
		sort.Strings(out.Admission.Devices)
	}
	for _, sess := range s.Sessions() {
		out.Sessions = append(out.Sessions, sess.Snapshot())
	}
	sort.Slice(out.Sessions, func(i, j int) bool {
		return out.Sessions[i].TunIP < out.Sessions[j].TunIP
	})
	return out
}

func hex32(v uint32) string {
	const digits = "0123456789abcdef"
	b := []byte("0x00000000")
	for i := 0; i < 8; i++ {
		b[9-i] = digits[(v>>(4*i))&0xf]
	}
	return string(b)
}

// atomicSnapshot is the per-session publication slot.
type atomicSnapshot = atomic.Pointer[SessionSnapshot]
