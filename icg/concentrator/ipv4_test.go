package concentrator

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestBuildAndParseUDPPacket(t *testing.T) {
	src := netip.MustParseAddrPort("198.51.100.10:53")
	dst := netip.MustParseAddrPort("172.16.25.19:41234")
	data := []byte("payload bytes, odd length")

	pkt := buildUDPPacket(src, dst, 0x1234, 64, data)

	// The IPv4 header checksum must verify: the client hands these straight to
	// the kernel, which drops anything malformed.
	if c := checksum(pkt[:20]); c != 0 {
		t.Errorf("IPv4 header checksum does not verify: %#x", c)
	}
	// And the UDP checksum over the pseudo-header.
	sa, da := src.Addr().As4(), dst.Addr().As4()
	saved := binary.BigEndian.Uint16(pkt[26:])
	binary.BigEndian.PutUint16(pkt[26:], 0)
	if want := udpChecksum(sa, da, pkt[20:]); want != saved {
		t.Errorf("UDP checksum = %#x, recomputed %#x", saved, want)
	}
	binary.BigEndian.PutUint16(pkt[26:], saved)

	ip, err := parseIPv4(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if ip.Src != src.Addr() || ip.Dst != dst.Addr() || ip.Proto != protoUDP {
		t.Fatalf("header round trip: %+v", ip)
	}
	d, err := parseUDP(ip)
	if err != nil {
		t.Fatal(err)
	}
	if d.Src != src || d.Dst != dst {
		t.Fatalf("ports round trip: %s -> %s", d.Src, d.Dst)
	}
	if !bytes.Equal(d.Data, data) {
		t.Fatalf("data = %q", d.Data)
	}
}

func TestParseIPv4Rejects(t *testing.T) {
	good := buildUDPPacket(netip.MustParseAddrPort("1.1.1.1:1"),
		netip.MustParseAddrPort("2.2.2.2:2"), 1, 64, []byte("x"))

	t.Run("short", func(t *testing.T) {
		if _, err := parseIPv4(good[:10]); !errors.Is(err, ErrTruncated) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("not v4", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[0] = 0x65
		if _, err := parseIPv4(bad); !errors.Is(err, ErrNotIPv4) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("total length lies", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		binary.BigEndian.PutUint16(bad[2:], 9999)
		if _, err := parseIPv4(bad); !errors.Is(err, ErrTruncated) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("fragmented", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		binary.BigEndian.PutUint16(bad[6:], 0x2000) // MF
		if _, err := parseIPv4(bad); !errors.Is(err, ErrFragmented) {
			t.Fatalf("err = %v", err)
		}
	})
}

// A real ICMP echo request lifted from the capture, to prove the parser copes
// with the frames the device actually sends.
func TestParseCapturedICMP(t *testing.T) {
	pkt := []byte{
		0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0xe6, 0x75,
		172, 16, 25, 19, 8, 8, 8, 8,
		0x08, 0x00, 0x5d, 0x85, 0x74, 0xcf, 0x07, 0x8d,
	}
	pkt = append(pkt, bytes.Repeat([]byte{0xa5}, 0x54-len(pkt))...)
	ip, err := parseIPv4(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if ip.Proto != protoICMP {
		t.Fatalf("proto = %d", ip.Proto)
	}
	if ip.Src.String() != "172.16.25.19" || ip.Dst.String() != "8.8.8.8" {
		t.Fatalf("%s -> %s", ip.Src, ip.Dst)
	}
	if ip.TTL != 255 {
		t.Fatalf("ttl = %d", ip.TTL)
	}
	if len(ip.Payload) != 0x54-20 {
		t.Fatalf("payload = %d bytes", len(ip.Payload))
	}
	if c := checksum(pkt[:20]); c != 0 {
		t.Errorf("the captured header checksum should verify, got %#x", c)
	}
}
