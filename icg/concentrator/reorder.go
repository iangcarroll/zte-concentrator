package concentrator

import "time"

// Reorder reassembles one of ICG's two GLOBAL sequence spaces.
//
// ICG stripes a single flow across every WAN leg, assigning each packet the
// next number from a per-direction counter shared by all legs (one counter for
// TCP, one for UDP — see ICG_WIRE_PROTOCOL.md §10). Packets therefore arrive
// out of order as a matter of course, and the receiver is responsible for
// putting them back in order, asking for what never turned up, and eventually
// giving up on it. This mirrors what the client does in tcp_sort.c /
// udp_chan_sort.c, including the two-stage "request retransmission, then skip"
// behaviour.
//
// Sequence numbers are uint32 and wrap; all comparisons go through a signed
// 32-bit difference so wrap-around is handled without special cases.
//
// Reorder is not safe for concurrent use; the owning Session serialises access.
type Reorder[T any] struct {
	// next is the sequence number we are waiting for — the client calls this
	// the "sort flag". Undefined until the reassembler latches on.
	next    uint32
	started bool

	// settle is how long to hold the very first packets before choosing a
	// starting position. Neither side declares one, so we have to infer it —
	// and because ICG stripes across legs, the first packet to ARRIVE is not
	// necessarily the first packet SENT. Latching onto it immediately (which
	// is what the client itself does) throws away everything below it. A short
	// settle window costs a few milliseconds once per session and makes the
	// start of a striped session lossless.
	settle    time.Duration
	firstSeen time.Time

	pend map[uint32]pending[T]

	// maxPend bounds memory. The client has the same protection
	// ("drop large packet to protect memory!!!"); when we hit the limit we
	// force-advance past the oldest gap rather than stalling for ever.
	maxPend int

	// retransmitAfter is how long a gap may persist before we ask the peer to
	// resend. skipAfter is how long before we give up and step over it.
	retransmitAfter time.Duration
	skipAfter       time.Duration

	blockedSince time.Time // when the current gap first blocked us
	lastRequest  time.Time // when we last asked for a retransmission

	// Stats, for operator visibility. A concentrator that silently skips is
	// indistinguishable from one that works.
	Delivered, Duplicated, Late, Skipped, Requested uint64
	MaxSeen                                         uint32
}

type pending[T any] struct {
	val T
	at  time.Time
}

// ReorderConfig tunes a Reorder. Zero values get sensible defaults chosen to
// sit inside the client's own tolerances (its retransmit timeout starts around
// 100 ms and its sort-block timeout around 1 s).
type ReorderConfig struct {
	MaxPending      int
	RetransmitAfter time.Duration
	SkipAfter       time.Duration

	// Settle is how long the first packets are buffered before the starting
	// sequence number is chosen. Zero means the package default; use a
	// negative value to latch onto the first packet immediately.
	Settle time.Duration
}

func NewReorder[T any](cfg ReorderConfig) *Reorder[T] {
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 4096
	}
	if cfg.RetransmitAfter <= 0 {
		cfg.RetransmitAfter = 60 * time.Millisecond
	}
	if cfg.SkipAfter <= 0 {
		cfg.SkipAfter = 1500 * time.Millisecond
	}
	switch {
	case cfg.Settle == 0:
		cfg.Settle = 25 * time.Millisecond
	case cfg.Settle < 0:
		cfg.Settle = 0
	}
	return &Reorder[T]{
		pend:            make(map[uint32]pending[T]),
		maxPend:         cfg.MaxPending,
		retransmitAfter: cfg.RetransmitAfter,
		skipAfter:       cfg.SkipAfter,
		settle:          cfg.Settle,
	}
}

// diff is seq - next as a signed distance, so that wrap-around behaves.
func diff(seq, next uint32) int32 { return int32(seq - next) }

// Push offers a packet. It returns every packet that is now deliverable, in
// sequence order — usually zero or one, but a run when the packet filled a gap.
//
// Neither side declares a starting sequence number, so the first packets are
// held for the settle window and the lowest of them becomes the start. Call
// Expire from a timer so a session that receives exactly one packet still
// makes progress.
func (r *Reorder[T]) Push(seq uint32, v T, now time.Time) []T {
	if !r.started {
		if r.firstSeen.IsZero() {
			r.firstSeen = now
			r.MaxSeen = seq
		}
		if diff(seq, r.MaxSeen) > 0 {
			r.MaxSeen = seq
		}
		if _, dup := r.pend[seq]; dup {
			r.Duplicated++
			return nil
		}
		r.pend[seq] = pending[T]{v, now}
		if now.Sub(r.firstSeen) < r.settle && len(r.pend) <= r.maxPend {
			return nil
		}
		return r.latch(now)
	}
	if diff(seq, r.MaxSeen) > 0 {
		r.MaxSeen = seq
	}

	d := diff(seq, r.next)
	switch {
	case d < 0:
		// Already delivered or already skipped. Almost always a retransmission
		// that raced the original.
		r.Late++
		return nil
	case d == 0:
		r.next++
		r.Delivered++
		out := append(make([]T, 0, 1), v)
		return r.drain(out)
	}

	if _, dup := r.pend[seq]; dup {
		r.Duplicated++
		return nil
	}
	r.pend[seq] = pending[T]{v, now}
	if r.blockedSince.IsZero() {
		r.blockedSince = now
	}
	if len(r.pend) > r.maxPend {
		// Memory pressure: step over the gap immediately.
		return r.skipToLowest(now)
	}
	return nil
}

// latch chooses the starting position — the lowest sequence number seen during
// the settle window — and delivers everything contiguous from it.
func (r *Reorder[T]) latch(now time.Time) []T {
	lowest, ok := r.lowest()
	if !ok {
		return nil
	}
	r.started = true
	r.next = lowest
	r.blockedSince = now
	return r.drain(nil)
}

// drain moves everything that has become contiguous out of the pending map.
func (r *Reorder[T]) drain(out []T) []T {
	for {
		p, ok := r.pend[r.next]
		if !ok {
			break
		}
		delete(r.pend, r.next)
		r.next++
		r.Delivered++
		out = append(out, p.val)
	}
	if len(r.pend) == 0 {
		r.blockedSince = time.Time{}
	} else {
		// A new gap starts now, not when the old one did.
		r.blockedSince = time.Now()
	}
	return out
}

// Missing reports the sequence numbers we are waiting for, capped at limit and
// rate-limited to one request per retransmitAfter, so that a persistent gap
// does not turn into a request storm. Call it from a timer.
func (r *Reorder[T]) Missing(now time.Time, limit int) []uint32 {
	if !r.started || len(r.pend) == 0 || r.blockedSince.IsZero() {
		return nil
	}
	if now.Sub(r.blockedSince) < r.retransmitAfter {
		return nil
	}
	if !r.lastRequest.IsZero() && now.Sub(r.lastRequest) < r.retransmitAfter {
		return nil
	}
	r.lastRequest = now

	// Everything from next up to the highest pending number that is absent.
	var out []uint32
	for s := r.next; diff(s, r.MaxSeen) <= 0 && len(out) < limit; s++ {
		if _, ok := r.pend[s]; !ok {
			out = append(out, s)
		}
	}
	r.Requested += uint64(len(out))
	return out
}

// Expire gives up on a gap that has blocked longer than skipAfter, stepping
// over it and returning whatever became deliverable. This is the client's
// "[UDPDL][SEQ SKIP] ... skip this pack!" behaviour: a permanently lost packet
// must not stall the whole tunnel.
func (r *Reorder[T]) Expire(now time.Time) []T {
	if !r.started {
		// Still settling: latch as soon as the window has passed, so a session
		// whose first packet is also its only packet is not held for ever.
		if len(r.pend) > 0 && now.Sub(r.firstSeen) >= r.settle {
			return r.latch(now)
		}
		return nil
	}
	if len(r.pend) == 0 || r.blockedSince.IsZero() {
		return nil
	}
	if now.Sub(r.blockedSince) < r.skipAfter {
		return nil
	}
	return r.skipToLowest(now)
}

// skipToLowest advances next to the lowest pending sequence number and drains.
func (r *Reorder[T]) skipToLowest(now time.Time) []T {
	lowest, ok := r.lowest()
	if !ok {
		return nil
	}
	if n := diff(lowest, r.next); n > 0 {
		r.Skipped += uint64(n)
	}
	r.next = lowest
	r.blockedSince = now
	return r.drain(nil)
}

func (r *Reorder[T]) lowest() (uint32, bool) {
	var best uint32
	first := true
	for s := range r.pend {
		if first || diff(s, best) < 0 {
			best, first = s, false
		}
	}
	return best, !first
}

// Ack is the cumulative acknowledgement to advertise: the highest sequence
// number below which everything has been delivered. The peer uses it to free
// its retransmission stash.
func (r *Reorder[T]) Ack() (uint32, bool) {
	if !r.started {
		return 0, false
	}
	return r.next - 1, true
}

// Pending is how many out-of-order packets are held.
func (r *Reorder[T]) Pending() int { return len(r.pend) }

// Reset returns the reassembler to its initial state. The client does this on
// every successful handshake (refresh_icg_resource), so we must too, or we
// would carry a stale sort position into a new session.
func (r *Reorder[T]) Reset() {
	r.started = false
	r.next = 0
	r.MaxSeen = 0
	r.pend = make(map[uint32]pending[T])
	r.blockedSince = time.Time{}
	r.lastRequest = time.Time{}
	r.firstSeen = time.Time{}
}
