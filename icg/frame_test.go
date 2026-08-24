package icg

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func mustFrame(t *testing.T, hexstr string) *Frame {
	t.Helper()
	b, err := hex.DecodeString(hexstr)
	if err != nil {
		t.Fatal(err)
	}
	f, n, err := Decode(b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(b) {
		t.Fatalf("consumed %d of %d", n, len(b))
	}
	return f
}

// A real ICG_UDP_CHNN_RTT_SYNC_ACK, straight from the capture. Kept inline so
// the header layout is pinned even if testdata is regenerated.
const rttSyncAckHex = "78563412" + "23000000" +
	"ac101912" + "03" + "06" + "00000000" +
	"e30f0000" + "a00100004eb2dc2f" + "a0010000a8dd242e" + "0401010000"

func TestDecodeKnownFrame(t *testing.T) {
	f := mustFrame(t, rttSyncAckHex)
	if f.Type != TypeHandshake || f.Opcode != HSRTTSyncAck {
		t.Fatalf("got %s/%d", f.Type, f.Opcode)
	}
	if f.Seq != 0 {
		t.Errorf("Seq = %d, want 0", f.Seq)
	}
	if got := f.TunIPAddr().String(); got != "172.16.25.18" {
		t.Errorf("TunIPAddr = %s, want 172.16.25.18", got)
	}
	r, err := ParseRTTBody(f.Body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Seq != 0x0fe3 {
		t.Errorf("rtt Seq = %#x, want 0xfe3", r.Seq)
	}
	// hi=0x1a0, lo=0x2fdcb24e -> 0x1a0<<32 | 0x2fdcb24e
	const wantClient = uint64(0x1a0)<<32 | 0x2fdcb24e
	if r.ClientMS != wantClient {
		t.Errorf("ClientMS = %d, want %d", r.ClientMS, wantClient)
	}
	// Sanity: that must be a plausible wall clock, not a nonsense magnitude.
	got := time.UnixMilli(int64(r.ClientMS)).UTC()
	if got.Year() != 2026 {
		t.Errorf("ClientMS decodes to %s, want a 2026 timestamp", got)
	}
	if r.Trailer != [5]byte{0x04, 0x01, 0x01, 0x00, 0x00} {
		t.Errorf("Trailer = %x", r.Trailer)
	}
}

func TestDecodeErrors(t *testing.T) {
	full, _ := hex.DecodeString(rttSyncAckHex)
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrShort},
		{"outer only partly", full[:5], ErrShort},
		{"body truncated", full[:20], ErrShort},
		{"bad magic", append([]byte{0, 0, 0, 0}, full[4:]...), ErrMagic},
		{"body len below sub-header", []byte{0x78, 0x56, 0x34, 0x12, 9, 0, 0, 0}, ErrBodyLen},
		{"body len absurd", []byte{0x78, 0x56, 0x34, 0x12, 0xff, 0xff, 0, 0}, ErrBodyLen},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Decode(tc.in, 0); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecodeRejectsForeignMagic(t *testing.T) {
	full, _ := hex.DecodeString(rttSyncAckHex)
	if _, _, err := Decode(full, 0xdeadbeef); !errors.Is(err, ErrMagic) {
		t.Fatalf("a frame with the wrong TunnelIdentifier must be rejected, got %v", err)
	}
}

func TestRoundTripAllocFree(t *testing.T) {
	f := mustFrame(t, rttSyncAckHex)
	// AppendTo must not need a fresh allocation when the caller supplies room.
	buf := make([]byte, 0, 256)
	buf = f.AppendTo(buf)
	if cap(buf) != 256 {
		t.Errorf("AppendTo reallocated: cap %d", cap(buf))
	}
	want, _ := hex.DecodeString(rttSyncAckHex)
	if !bytes.Equal(buf, want) {
		t.Errorf("round trip mismatch\n got %x\nwant %x", buf, want)
	}
}

// TestStreamReaderConcatenated: the client packs several frames into one
// segment, so the reader must return them all without another read.
func TestStreamReaderConcatenated(t *testing.T) {
	one, _ := hex.DecodeString(rttSyncAckHex)
	stream := bytes.Repeat(one, 3)
	sr := NewStreamReader(bytes.NewReader(stream), 0)
	for i := 0; i < 3; i++ {
		f, err := sr.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if f.Opcode != HSRTTSyncAck {
			t.Fatalf("frame %d: opcode %d", i, f.Opcode)
		}
	}
	if _, err := sr.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
	if sr.Resyncs != 0 {
		t.Errorf("Resyncs = %d, want 0", sr.Resyncs)
	}
}

// byteReader hands out one byte at a time, the worst case for a deframer.
type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	p[0] = r.b[r.i]
	r.i++
	return 1, nil
}

// TestStreamReaderSplit: a frame may span segments, including across the
// 8-byte outer header, so a one-byte-at-a-time reader must still work.
func TestStreamReaderSplit(t *testing.T) {
	one, _ := hex.DecodeString(rttSyncAckHex)
	sr := NewStreamReader(&byteReader{b: bytes.Repeat(one, 2)}, 0)
	for i := 0; i < 2; i++ {
		if _, err := sr.Next(); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
	if _, err := sr.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

// TestStreamReaderResync: framing loss is a real failure mode on this protocol
// (the client has find_tcp_tunnel_header_again for exactly this), so garbage
// ahead of a valid frame must be skipped and counted, not fatal.
func TestStreamReaderResync(t *testing.T) {
	one, _ := hex.DecodeString(rttSyncAckHex)
	stream := append([]byte("junkjunkjunk\x00\x01\x02"), one...)
	sr := NewStreamReader(bytes.NewReader(stream), 0)
	f, err := sr.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if f.Opcode != HSRTTSyncAck {
		t.Fatalf("opcode %d", f.Opcode)
	}
	if sr.Resyncs == 0 {
		t.Error("Resyncs was not incremented")
	}
}

// TestStreamReaderResyncOnMagicInGarbage: the magic can appear inside the
// garbage; a bad body length there must trigger another resync rather than
// aborting the connection.
func TestStreamReaderResyncPastFakeMagic(t *testing.T) {
	one, _ := hex.DecodeString(rttSyncAckHex)
	fake := []byte{0x78, 0x56, 0x34, 0x12, 0x01, 0x00, 0x00, 0x00} // body_len 1: invalid
	sr := NewStreamReader(bytes.NewReader(append(fake, one...)), 0)
	f, err := sr.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if f.Opcode != HSRTTSyncAck {
		t.Fatalf("opcode %d", f.Opcode)
	}
}

func TestStreamReaderOversizeFrame(t *testing.T) {
	// A frame claiming more than MaxBodyLen must be rejected as a framing
	// error, not buffered forever.
	hdr := []byte{0x78, 0x56, 0x34, 0x12}
	hdr = append(hdr, 0x00, 0x90, 0x00, 0x00) // body_len 0x9000 > MaxBodyLen
	sr := NewStreamReader(bytes.NewReader(hdr), 0)
	if _, err := sr.Next(); err == nil {
		t.Fatal("want an error for an oversize frame")
	}
}

func TestTCPBodyRoundTrip(t *testing.T) {
	in := TCPBody{
		Seq:    0x5d02,
		Opcode: TCPPayload,
		Src:    netip.MustParseAddrPort("192.168.0.245:62701"),
		Dst:    netip.MustParseAddrPort("198.51.100.10:443"),
		Data:   []byte("hello"),
	}
	enc := in.AppendTo(nil)
	if len(enc) != TCPHdrLen+5 {
		t.Fatalf("encoded %d bytes", len(enc))
	}
	out, err := ParseTCPBody(enc)
	if err != nil {
		t.Fatal(err)
	}
	if out.Seq != in.Seq || out.Opcode != in.Opcode || out.Src != in.Src || out.Dst != in.Dst {
		t.Fatalf("mismatch: %+v vs %+v", out, in)
	}
	if string(out.Data) != "hello" {
		t.Fatalf("data = %q", out.Data)
	}
	// The downlink flips the tuple.
	down := out.UpFlow().DownBody(7, TCPPayload, []byte("hi"))
	if down.Src != in.Dst || down.Dst != in.Src {
		t.Fatalf("DownBody did not swap the tuple: %s -> %s", down.Src, down.Dst)
	}
}

func TestTCPBodyShort(t *testing.T) {
	if _, err := ParseTCPBody(make([]byte, TCPHdrLen-1)); !errors.Is(err, ErrBodyShort) {
		t.Fatal("want ErrBodyShort")
	}
}

func TestSeqListPadsToFixedLength(t *testing.T) {
	// The client always sends 204 bytes regardless of count; matching that
	// exactly is what keeps its parser happy.
	enc := AppendSeqList(nil, []uint32{1, 2, 3})
	if len(enc) != SeqListLen {
		t.Fatalf("len = %d, want %d", len(enc), SeqListLen)
	}
	got, err := ParseSeqList(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 1 || got[2] != 3 {
		t.Fatalf("got %v", got)
	}
}

func TestSeqListTruncatesAtMax(t *testing.T) {
	in := make([]uint32, SeqListMax+10)
	for i := range in {
		in[i] = uint32(i)
	}
	got, err := ParseSeqList(AppendSeqList(nil, in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != SeqListMax {
		t.Fatalf("len = %d, want %d", len(got), SeqListMax)
	}
}

func TestSeqListRejectsBadCount(t *testing.T) {
	b := make([]byte, SeqListLen)
	b[3] = 99 // count 99 > SeqListMax
	if _, err := ParseSeqList(b); err == nil {
		t.Fatal("want an error for an over-large count")
	}
}

func TestRTTReplyPreservesClientClock(t *testing.T) {
	// The client computes rtt = its_now - ClientMS, so mangling ClientMS makes
	// the leg look dead. This is the single most important invariant on the
	// UDP legs.
	in := RTTBody{Seq: 42, ClientMS: 1_787_509_093_938, Trailer: [5]byte{4, 1, 1, 0, 0}}
	out := in.Reply(time.UnixMilli(1_787_509_093_999))
	if out.ClientMS != in.ClientMS {
		t.Fatalf("ClientMS changed: %d -> %d", in.ClientMS, out.ClientMS)
	}
	if out.ServerMS != 1_787_509_093_999 {
		t.Fatalf("ServerMS = %d", out.ServerMS)
	}
	if out.Seq != in.Seq || out.Trailer != in.Trailer {
		t.Fatal("Reply must not disturb Seq or Trailer")
	}
}

func TestOpcodeNamesMatchDeviceStrings(t *testing.T) {
	// These strings are grepped against /logfs/zte_icg_agg_log, so typos are
	// worse than they look.
	cases := map[string]string{
		OpcodeName(TypeHandshake, HSReqWithConfig): "ICG_HANDSHAKE_REQ_WITH_CONFIG",
		OpcodeName(TypeHandshake, HSServerAck):     "ICG_SERVER_HANDSHAKE_ACK",
		OpcodeName(TypeAck, AckTCPRetranRange):     "TCP_REQUEST_TRANS_RANGE",
		OpcodeName(TypeAck, AckUDPCumulative):      "UDP_ACCUMU_ACK",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if s := OpcodeName(TypeAck, 200); !strings.Contains(s, "200") {
		t.Errorf("unknown opcode should render its number, got %q", s)
	}
}
