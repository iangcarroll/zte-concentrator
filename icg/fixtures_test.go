package icg

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

// fixture is one redacted frame captured from a real MU5252 <-> ZTE
// concentrator session. See icg/testdata/frames.txt.
type fixture struct {
	line  int
	leg   string // "tcp" | "udp"
	dir   string // "cli2srv" | "srv2cli"
	typ   Type
	op    uint8
	bytes []byte
}

func loadFixtures(t *testing.T) []fixture {
	t.Helper()
	f, err := os.Open("testdata/frames.txt")
	if err != nil {
		t.Fatalf("open fixtures: %v", err)
	}
	defer f.Close()

	var out []fixture
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) != 5 {
			t.Fatalf("line %d: want 5 fields, got %d", n, len(p))
		}
		ty, err := strconv.Atoi(p[2])
		if err != nil {
			t.Fatalf("line %d: type: %v", n, err)
		}
		op, err := strconv.Atoi(p[3])
		if err != nil {
			t.Fatalf("line %d: opcode: %v", n, err)
		}
		raw, err := hex.DecodeString(p[4])
		if err != nil {
			t.Fatalf("line %d: hex: %v", n, err)
		}
		out = append(out, fixture{n, p[0], p[1], Type(ty), uint8(op), raw})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no fixtures loaded")
	}
	return out
}

// TestFixtureRoundTrip is the load-bearing test: every real frame must decode
// to the type/opcode the capture was labelled with, and re-encode byte for
// byte. A single wrong offset or endianness anywhere in the header breaks it.
func TestFixtureRoundTrip(t *testing.T) {
	for _, fx := range loadFixtures(t) {
		f, n, err := Decode(fx.bytes, 0)
		if err != nil {
			t.Errorf("line %d: decode: %v", fx.line, err)
			continue
		}
		if n != len(fx.bytes) {
			t.Errorf("line %d: consumed %d of %d bytes", fx.line, n, len(fx.bytes))
		}
		if f.Type != fx.typ || f.Opcode != fx.op {
			t.Errorf("line %d: decoded %s/%d, capture said %s/%d",
				fx.line, f.Type, f.Opcode, fx.typ, fx.op)
		}
		if got := f.Encode(); !bytes.Equal(got, fx.bytes) {
			t.Errorf("line %d: re-encode mismatch\n got %x\nwant %x", fx.line, got, fx.bytes)
		}
	}
}

// TestFixtureCoverage guards against the fixture file silently losing a
// message class — which would make the other tests pass for the wrong reason.
func TestFixtureCoverage(t *testing.T) {
	seen := map[string]int{}
	for _, fx := range loadFixtures(t) {
		seen[fx.leg+"/"+fx.typ.String()+"/"+OpcodeName(fx.typ, fx.op)]++
	}
	// Exactly the classes the 2026-08-23 capture contained. The handshake
	// proper (opcodes 1/2/3) is absent because the capture began after the
	// session was already established; those paths are covered by unit tests
	// derived from the disassembly instead.
	want := []string{
		"tcp/ICMP/0",
		"tcp/TCP_DOWN/0",
		"tcp/HANDSHAKE/ICG_KEEPALIVE",
		"tcp/ACK/TCP_REQUEST_TRANS_RANGE",
		"tcp/ACK/TCP_ACCUMU_ACK",
		"tcp/ACK/TUNNEL_DETECT",
		"tcp/TCP_UP/0",
		"udp/HANDSHAKE/ICG_UDP_CHNN_RTT_SYNC",
		"udp/HANDSHAKE/ICG_UDP_CHNN_RTT_SYNC_ACK",
		"udp/HANDSHAKE/ICG_UDP_CHNN_RTT_ACK",
	}
	for _, w := range want {
		if seen[w] == 0 {
			t.Errorf("fixture class missing: %s", w)
		}
		delete(seen, w)
	}
	for extra, n := range seen {
		t.Logf("note: fixture file has an unexpected class %s (%d frames) — "+
			"if that is a new capture, add it to the want list", extra, n)
	}
}

// TestFixtureTCPBodies checks the §7 body layout against real frames: the
// 5-tuple must come out as plausible addresses and the direction must match
// the leg the frame was seen on.
func TestFixtureTCPBodies(t *testing.T) {
	var up, down int
	for _, fx := range loadFixtures(t) {
		if fx.typ != TypeTCPUp && fx.typ != TypeTCPDown {
			continue
		}
		f, _, err := Decode(fx.bytes, 0)
		if err != nil {
			t.Fatalf("line %d: %v", fx.line, err)
		}
		b, err := ParseTCPBody(f.Body)
		if err != nil {
			t.Errorf("line %d: %v", fx.line, err)
			continue
		}
		if !b.Src.IsValid() || !b.Dst.IsValid() || b.Src.Port() == 0 || b.Dst.Port() == 0 {
			t.Errorf("line %d: implausible tuple %s -> %s", fx.line, b.Src, b.Dst)
		}
		switch b.Opcode {
		case TCPConnect, TCPDisconnect:
			if len(b.Data) != 0 {
				t.Errorf("line %d: %s frame carries %d data bytes", fx.line, b.Opcode, len(b.Data))
			}
		case TCPPayload:
			if len(b.Data) == 0 {
				t.Errorf("line %d: PAYLOAD frame carries no data", fx.line)
			}
		default:
			t.Errorf("line %d: unexpected tcp opcode %s", fx.line, b.Opcode)
		}
		// The LAN client is always the RFC1918 side. On the uplink it is Src,
		// on the downlink Dst.
		if fx.typ == TypeTCPUp {
			up++
			if !b.Src.Addr().IsPrivate() {
				t.Errorf("line %d: uplink src %s is not the LAN client", fx.line, b.Src)
			}
		} else {
			down++
			if !b.Dst.Addr().IsPrivate() {
				t.Errorf("line %d: downlink dst %s is not the LAN client", fx.line, b.Dst)
			}
		}
		// Round-trip the body.
		if got := b.AppendTo(nil); !bytes.Equal(got, f.Body) {
			t.Errorf("line %d: body re-encode mismatch", fx.line)
		}
	}
	if up == 0 || down == 0 {
		t.Fatalf("need both directions of TCP data, got up=%d down=%d", up, down)
	}
}

// TestFixtureRTT proves the §4.3 middle-endian timestamp split: the client's
// timestamps must land in a sane wall-clock window, and the server's must be
// zero on a SYNC and set on a SYNC_ACK.
func TestFixtureRTT(t *testing.T) {
	// The capture is from 2026-08-23. Accept a wide window so the test is not
	// brittle, but tight enough that a wrong hi/lo split (which lands ~1e18)
	// or a byte-swap fails.
	const loMS = 1_700_000_000_000 // 2023-11
	const hiMS = 1_900_000_000_000 // 2030-03

	var sync, ack, rttack int
	for _, fx := range loadFixtures(t) {
		if fx.typ != TypeHandshake || fx.op < HSRTTSync {
			continue
		}
		f, _, err := Decode(fx.bytes, 0)
		if err != nil {
			t.Fatalf("line %d: %v", fx.line, err)
		}
		r, err := ParseRTTBody(f.Body)
		if err != nil {
			t.Errorf("line %d: %v", fx.line, err)
			continue
		}
		if r.ClientMS < loMS || r.ClientMS > hiMS {
			t.Errorf("line %d: client timestamp %d out of range — hi/lo split wrong?",
				fx.line, r.ClientMS)
		}
		switch fx.op {
		case HSRTTSync:
			sync++
			if r.ServerMS != 0 {
				t.Errorf("line %d: SYNC should not carry a server timestamp, got %d", fx.line, r.ServerMS)
			}
		case HSRTTSyncAck, HSRTTAck:
			if fx.op == HSRTTSyncAck {
				ack++
			} else {
				rttack++
			}
			if r.ServerMS < loMS || r.ServerMS > hiMS {
				t.Errorf("line %d: server timestamp %d out of range", fx.line, r.ServerMS)
			}
		}
		if got := r.AppendTo(nil); !bytes.Equal(got, f.Body) {
			t.Errorf("line %d: rtt body re-encode mismatch\n got %x\nwant %x", fx.line, got, f.Body)
		}
	}
	if sync == 0 || ack == 0 || rttack == 0 {
		t.Fatalf("want all three RTT opcodes, got sync=%d ack=%d rttack=%d", sync, ack, rttack)
	}
}

// TestFixtureRTTAckIsVerbatimEcho encodes the observation from the capture that
// the client's ICG_UDP_CHNN_RTT_ACK repeats the server's SYNC_ACK payload
// byte for byte. That is what lets a concentrator treat opcode 7 as a no-op.
func TestFixtureRTTAckEchoesSyncAck(t *testing.T) {
	acks := map[uint32][]byte{}   // seq -> server SYNC_ACK payload
	echoes := map[uint32][]byte{} // seq -> client RTT_ACK payload
	for _, fx := range loadFixtures(t) {
		if fx.typ != TypeHandshake {
			continue
		}
		f, _, err := Decode(fx.bytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseRTTBody(f.Body)
		if err != nil {
			continue
		}
		switch fx.op {
		case HSRTTSyncAck:
			acks[r.Seq] = append([]byte(nil), f.Body...)
		case HSRTTAck:
			echoes[r.Seq] = append([]byte(nil), f.Body...)
		}
	}
	matched := 0
	for seq, echo := range echoes {
		ack, ok := acks[seq]
		if !ok {
			continue
		}
		if !bytes.Equal(ack, echo) {
			t.Errorf("seq %d: RTT_ACK is not a verbatim echo of SYNC_ACK\n ack %x\necho %x", seq, ack, echo)
		}
		matched++
	}
	if matched == 0 {
		t.Skip("no SYNC_ACK/RTT_ACK pair with a common seq in the fixture sample")
	}
}

// TestFixtureSeqList checks the §5.1 retransmit-request layout on real frames.
func TestFixtureSeqList(t *testing.T) {
	found := 0
	for _, fx := range loadFixtures(t) {
		if fx.typ != TypeAck || (fx.op != AckTCPRetranRange && fx.op != AckUDPRetranRange) {
			continue
		}
		f, _, err := Decode(fx.bytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(f.Body) != SeqListLen {
			t.Errorf("line %d: seq list body is %d bytes, want %d", fx.line, len(f.Body), SeqListLen)
		}
		seqs, err := ParseSeqList(f.Body)
		if err != nil {
			t.Errorf("line %d: %v", fx.line, err)
			continue
		}
		if len(seqs) == 0 {
			t.Errorf("line %d: empty seq list", fx.line)
			continue
		}
		// The sub-header seq is documented to equal the first requested seq.
		if f.Seq != seqs[0] {
			t.Errorf("line %d: header seq %d != first requested seq %d", fx.line, f.Seq, seqs[0])
		}
		if got := AppendSeqList(nil, seqs); !bytes.Equal(got, f.Body) {
			t.Errorf("line %d: seq list re-encode mismatch", fx.line)
		}
		found++
	}
	if found == 0 {
		t.Fatal("no retransmit-range frames in fixtures")
	}
}

// TestFixtureRawIPPayloads checks that type 0 and type 1 bodies really are
// whole IPv4 packets, which is the §8 correction.
func TestFixtureRawIPPayloads(t *testing.T) {
	found := 0
	for _, fx := range loadFixtures(t) {
		if fx.typ != TypeUDP && fx.typ != TypeICMP {
			continue
		}
		f, _, err := Decode(fx.bytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		p := f.Body
		if len(p) < 20 {
			t.Errorf("line %d: %s payload is %d bytes, too short for IPv4", fx.line, fx.typ, len(p))
			continue
		}
		if v := p[0] >> 4; v != 4 {
			t.Errorf("line %d: %s payload IP version %d, want 4", fx.line, fx.typ, v)
		}
		if total := int(p[2])<<8 | int(p[3]); total != len(p) {
			t.Errorf("line %d: IPv4 total length %d != payload %d", fx.line, total, len(p))
		}
		if fx.typ == TypeICMP {
			if p[9] != 1 {
				t.Errorf("line %d: TypeICMP carries IP proto %d, want 1", fx.line, p[9])
			}
			if f.Seq != 0 {
				t.Errorf("line %d: ICMP frames are unsequenced, got seq %d", fx.line, f.Seq)
			}
		}
		found++
	}
	if found == 0 {
		t.Fatal("no raw-IP frames in fixtures")
	}
}

// TestFixtureKeepaliveTunnelID exercises the fake-ping tunnel-id extraction,
// which is how a concentrator tells the WAN legs apart on the TCP tunnel.
func TestFixtureKeepaliveTunnelID(t *testing.T) {
	ids := map[int]int{}
	for _, fx := range loadFixtures(t) {
		if fx.typ != TypeHandshake || fx.op != HSKeepalive {
			continue
		}
		f, _, err := Decode(fx.bytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		id, ok := TunnelIDFromFakePing(f.Body)
		if !ok {
			t.Errorf("line %d: keepalive carried no tunnel id TLV", fx.line)
			continue
		}
		if id < 0 || id > 64 {
			t.Errorf("line %d: implausible tunnel id %d", fx.line, id)
		}
		ids[id]++
	}
	if len(ids) < 2 {
		t.Errorf("expected keepalives from several tunnels, saw ids %v", ids)
	}
}
