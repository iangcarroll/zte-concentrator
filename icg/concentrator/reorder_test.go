package concentrator

import (
	"reflect"
	"testing"
	"time"
)

var t0 = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

func TestReorderInOrder(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: -1})
	for i := 100; i < 105; i++ {
		got := r.Push(uint32(i), i, t0)
		if !reflect.DeepEqual(got, []int{i}) {
			t.Fatalf("seq %d: got %v", i, got)
		}
	}
	if r.Pending() != 0 {
		t.Fatalf("pending = %d", r.Pending())
	}
	if ack, ok := r.Ack(); !ok || ack != 104 {
		t.Fatalf("Ack = %d, %v", ack, ok)
	}
}

// With Settle disabled the first packet defines the starting position, which
// is what the client itself does ("[TCPDL][SORT] ... init!").
func TestReorderLatchesOntoFirstSeqWhenSettleDisabled(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: -1})
	if got := r.Push(0x5d02, 1, t0); len(got) != 1 {
		t.Fatalf("first packet must deliver immediately, got %v", got)
	}
	if _, ok := r.Ack(); !ok {
		t.Fatal("Ack should be available after the first packet")
	}
}

// The reason the settle window exists: ICG stripes across legs, so the first
// packet to ARRIVE need not be the first packet SENT. Latching onto it
// immediately would discard everything below it — which is a real data loss at
// the start of every striped session.
func TestReorderSettleWindowRecoversEarlierSeqs(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: 30 * time.Millisecond})

	// A later packet wins the race off a faster WAN.
	if got := r.Push(104, 104, t0); got != nil {
		t.Fatalf("must not latch during the settle window, got %v", got)
	}
	// The earlier ones show up over the slower one.
	if got := r.Push(101, 101, t0.Add(time.Millisecond)); got != nil {
		t.Fatalf("still settling, got %v", got)
	}
	r.Push(102, 102, t0.Add(2*time.Millisecond))
	r.Push(103, 103, t0.Add(3*time.Millisecond))

	got := r.Push(105, 105, t0.Add(40*time.Millisecond)) // window has passed
	want := []int{101, 102, 103, 104, 105}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v — nothing may be lost at session start", got, want)
	}
	if r.Late != 0 {
		t.Errorf("Late = %d; the settle window exists so these are not late", r.Late)
	}
}

// A session whose first packet is also its only packet must still make
// progress once the window elapses; Expire is what unblocks it.
func TestReorderSettleWindowExpires(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: 30 * time.Millisecond})
	if got := r.Push(7, 7, t0); got != nil {
		t.Fatalf("got %v", got)
	}
	if got := r.Expire(t0.Add(10 * time.Millisecond)); got != nil {
		t.Fatalf("too early, got %v", got)
	}
	got := r.Expire(t0.Add(40 * time.Millisecond))
	if !reflect.DeepEqual(got, []int{7}) {
		t.Fatalf("got %v, want [7]", got)
	}
	if ack, ok := r.Ack(); !ok || ack != 7 {
		t.Fatalf("Ack = %d, %v", ack, ok)
	}
}

// Memory pressure must cut the settle window short rather than buffering
// unboundedly.
func TestReorderSettleWindowRespectsMemoryCap(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: time.Hour, MaxPending: 3})
	r.Push(10, 10, t0)
	r.Push(11, 11, t0)
	r.Push(12, 12, t0)
	got := r.Push(13, 13, t0)
	if len(got) != 4 {
		t.Fatalf("got %v, want the buffer flushed at the cap", got)
	}
}

func TestReorderFillsGapAndDrainsRun(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: -1})
	r.Push(10, 10, t0)
	// 12, 13, 14 arrive before 11.
	for _, s := range []uint32{12, 13, 14} {
		if got := r.Push(s, int(s), t0); got != nil {
			t.Fatalf("seq %d should be held, got %v", s, got)
		}
	}
	if r.Pending() != 3 {
		t.Fatalf("pending = %d, want 3", r.Pending())
	}
	got := r.Push(11, 11, t0)
	if !reflect.DeepEqual(got, []int{11, 12, 13, 14}) {
		t.Fatalf("got %v, want the whole run", got)
	}
	if r.Pending() != 0 {
		t.Fatalf("pending = %d", r.Pending())
	}
}

func TestReorderDropsLateAndDuplicate(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: -1})
	r.Push(10, 10, t0)
	r.Push(11, 11, t0)
	if got := r.Push(10, 10, t0); got != nil {
		t.Fatalf("a re-delivered packet must be dropped, got %v", got)
	}
	if r.Late != 1 {
		t.Fatalf("Late = %d", r.Late)
	}
	r.Push(20, 20, t0)
	if got := r.Push(20, 20, t0); got != nil {
		t.Fatalf("a duplicate pending packet must be dropped, got %v", got)
	}
	if r.Duplicated != 1 {
		t.Fatalf("Duplicated = %d", r.Duplicated)
	}
}

func TestReorderMissingIsRateLimited(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: -1, RetransmitAfter: 50 * time.Millisecond})
	r.Push(10, 10, t0)
	r.Push(13, 13, t0) // gap: 11, 12

	if got := r.Missing(t0, 10); got != nil {
		t.Fatalf("must not ask before RetransmitAfter, got %v", got)
	}
	at := t0.Add(60 * time.Millisecond)
	got := r.Missing(at, 10)
	if !reflect.DeepEqual(got, []uint32{11, 12}) {
		t.Fatalf("got %v, want [11 12]", got)
	}
	if again := r.Missing(at.Add(time.Millisecond), 10); again != nil {
		t.Fatalf("must rate-limit repeat requests, got %v", again)
	}
	if later := r.Missing(at.Add(100*time.Millisecond), 10); len(later) != 2 {
		t.Fatalf("should ask again after the interval, got %v", later)
	}
}

func TestReorderMissingRespectsLimit(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: -1, RetransmitAfter: 0})
	r.Push(0, 0, t0)
	r.Push(100, 100, t0)
	got := r.Missing(t0.Add(time.Second), 5)
	if len(got) != 5 || got[0] != 1 || got[4] != 5 {
		t.Fatalf("got %v", got)
	}
}

func TestReorderExpireSkipsPermanentLoss(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: -1, SkipAfter: 100 * time.Millisecond})
	r.Push(10, 10, t0)
	r.Push(13, 13, t0)

	if got := r.Expire(t0.Add(50 * time.Millisecond)); got != nil {
		t.Fatalf("must not skip early, got %v", got)
	}
	got := r.Expire(t0.Add(200 * time.Millisecond))
	if !reflect.DeepEqual(got, []int{13}) {
		t.Fatalf("got %v, want [13]", got)
	}
	if r.Skipped != 2 { // 11 and 12
		t.Fatalf("Skipped = %d, want 2", r.Skipped)
	}
	// And the stream continues from there.
	if out := r.Push(14, 14, t0); !reflect.DeepEqual(out, []int{14}) {
		t.Fatalf("got %v", out)
	}
}

// A stalled tunnel must not grow without bound; the client protects itself the
// same way ("drop large packet to protect memory!!!").
func TestReorderMemoryCapForcesProgress(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: -1, MaxPending: 4})
	r.Push(0, 0, t0)
	for _, s := range []uint32{5, 6, 7, 8} {
		r.Push(s, int(s), t0)
	}
	if r.Pending() != 4 {
		t.Fatalf("pending = %d", r.Pending())
	}
	got := r.Push(9, 9, t0) // exceeds the cap
	if len(got) != 5 {
		t.Fatalf("cap breach should flush the run, got %v", got)
	}
	if r.Pending() != 0 {
		t.Fatalf("pending = %d", r.Pending())
	}
}

// uint32 sequence spaces wrap; nothing may special-case it.
func TestReorderWrapAround(t *testing.T) {
	r := NewReorder[uint32](ReorderConfig{Settle: -1})
	start := uint32(0xfffffffe)
	r.Push(start, start, t0)
	if got := r.Push(start+1, start+1, t0); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	// Now 0 and 1, i.e. wrapped.
	if got := r.Push(1, 1, t0); got != nil {
		t.Fatalf("1 should be held while 0 is missing, got %v", got)
	}
	got := r.Push(0, 0, t0)
	if !reflect.DeepEqual(got, []uint32{0, 1}) {
		t.Fatalf("got %v, want [0 1] across the wrap", got)
	}
	// And a pre-wrap sequence number is now "late", not "far in the future".
	if out := r.Push(0xfffffff0, 0, t0); out != nil {
		t.Fatalf("pre-wrap seq must be treated as late, got %v", out)
	}
}

func TestReorderResetClearsPosition(t *testing.T) {
	r := NewReorder[int](ReorderConfig{Settle: -1})
	r.Push(500, 500, t0)
	r.Push(600, 600, t0)
	r.Reset()
	if r.Pending() != 0 {
		t.Fatalf("pending = %d after Reset", r.Pending())
	}
	if _, ok := r.Ack(); ok {
		t.Fatal("Ack must be unavailable after Reset")
	}
	// A fresh session may legitimately start at a lower number.
	if got := r.Push(1, 1, t0); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}
