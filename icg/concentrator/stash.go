package concentrator

// stash holds encoded downlink frames so that the peer's retransmission
// requests can be honoured.
//
// ICG puts reliability above the tunnel rather than inside it: the receiver
// asks for specific global sequence numbers (§5.1) and the sender is expected
// to still have them. Cumulative ACKs (§5) are what lets the sender let go.
// The client keeps the mirror of this in src/handle/icg_send_table.c.
//
// Not safe for concurrent use; the owning Session serialises access.
type stash struct {
	m     map[uint32][]byte
	order []uint32 // insertion order, for the memory cap
	limit int

	Hits, Misses uint64
}

func newStash(limit int) *stash {
	if limit <= 0 {
		limit = 8192
	}
	return &stash{m: make(map[uint32][]byte), limit: limit}
}

func (s *stash) put(seq uint32, frame []byte) {
	if _, ok := s.m[seq]; !ok {
		s.order = append(s.order, seq)
	}
	s.m[seq] = frame
	// Evict oldest-first if we are over the cap. A peer that asks for
	// something this old is not going to recover by waiting.
	for len(s.m) > s.limit && len(s.order) > 0 {
		old := s.order[0]
		s.order = s.order[1:]
		delete(s.m, old)
	}
}

func (s *stash) get(seq uint32) ([]byte, bool) {
	f, ok := s.m[seq]
	if ok {
		s.Hits++
	} else {
		s.Misses++
	}
	return f, ok
}

// ackUpTo frees everything at or below seq, using the same wrapping comparison
// as the reassembler so a cumulative ACK across the uint32 boundary works.
func (s *stash) ackUpTo(seq uint32) {
	keep := s.order[:0]
	for _, q := range s.order {
		if diff(q, seq) <= 0 {
			delete(s.m, q)
			continue
		}
		keep = append(keep, q)
	}
	s.order = keep
}

func (s *stash) len() int { return len(s.m) }
