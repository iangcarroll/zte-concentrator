package concentrator

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// A Notice is a diagnosable event worth showing an operator, kept in memory so
// the API and UI can show "what went wrong recently" without anyone having to
// find journalctl.
//
// This exists because of how the device behaves: zte_icg_agg gives its own
// operator no useful signal when a self-hosted concentrator rejects it, so the
// concentrator has to volunteer the explanation. Every notice therefore carries
// a Fix — a concrete next action — rather than only what happened.
type Notice struct {
	At    time.Time `json:"at"`
	Level string    `json:"level"` // "warn" | "info"
	Kind  string    `json:"kind"`  // stable machine-readable category
	Msg   string    `json:"msg"`
	Fix   string    `json:"fix,omitempty"`
	Peer  string    `json:"peer,omitempty"`
	Count int       `json:"count"` // repeats collapsed into one entry
}

const maxNotices = 200

type noticeLog struct {
	mu   sync.Mutex
	ring []Notice
	// dedup collapses a repeating notice (a scanner, a device in a retry loop)
	// into a single entry with a count, so the list stays readable.
	index map[string]int
}

func (n *noticeLog) add(nt Notice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.index == nil {
		n.index = map[string]int{}
	}
	key := nt.Kind + "\x00" + nt.Peer + "\x00" + nt.Msg
	if i, ok := n.index[key]; ok && i < len(n.ring) && n.ring[i].Kind == nt.Kind {
		n.ring[i].Count++
		n.ring[i].At = nt.At
		return
	}
	nt.Count = 1
	n.ring = append(n.ring, nt)
	n.index[key] = len(n.ring) - 1
	if len(n.ring) > maxNotices {
		drop := len(n.ring) - maxNotices
		n.ring = n.ring[drop:]
		// Rebuild the index: the slice shifted underneath it.
		n.index = make(map[string]int, len(n.ring))
		for i, e := range n.ring {
			n.index[e.Kind+"\x00"+e.Peer+"\x00"+e.Msg] = i
		}
	}
}

func (n *noticeLog) snapshot() []Notice {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Notice, len(n.ring))
	copy(out, n.ring)
	// Newest first: an operator reads the top of the list.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Notices returns the recent diagnosable events, newest first.
func (s *Server) Notices() []Notice { return s.notices.snapshot() }

// notice records an event and logs it. kind should be stable; fix should tell
// the operator what to actually do.
func (s *Server) notice(log *slog.Logger, level, kind, peer, fix, format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	s.notices.add(Notice{
		At: time.Now(), Level: level, Kind: kind, Msg: msg, Fix: fix, Peer: peer,
	})
	if log == nil {
		log = s.log
	}
	args := []any{"kind", kind}
	if peer != "" {
		args = append(args, "peer", peer)
	}
	if fix != "" {
		args = append(args, "fix", fix)
	}
	if level == "warn" {
		log.Warn(msg, args...)
	} else {
		log.Info(msg, args...)
	}
}
