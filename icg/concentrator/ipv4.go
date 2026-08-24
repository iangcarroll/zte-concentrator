package concentrator

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Tunnelled UDP and ICMP arrive as complete raw IPv4 packets (see
// ICG_WIRE_PROTOCOL.md §8) — the bytes the client read off tun0. The
// concentrator therefore has to do a small amount of IP-layer work that the
// TCP path, which carries a parsed 5-tuple, does not need.
//
// This is deliberately a minimal, allocation-light IPv4 helper rather than a
// dependency: we only ever handle IPv4, unfragmented, UDP or ICMP.

var (
	ErrNotIPv4    = errors.New("concentrator: not an IPv4 packet")
	ErrFragmented = errors.New("concentrator: fragmented IPv4 not supported")
	ErrTruncated  = errors.New("concentrator: truncated IPv4 packet")
)

const (
	protoICMP = 1
	protoUDP  = 17
)

// ipv4 is a parsed IPv4 header plus its payload, aliasing the input buffer.
type ipv4 struct {
	Src, Dst netip.Addr
	Proto    uint8
	TTL      uint8
	ID       uint16
	Payload  []byte
}

func parseIPv4(b []byte) (ipv4, error) {
	var p ipv4
	if len(b) < 20 {
		return p, ErrTruncated
	}
	if b[0]>>4 != 4 {
		return p, ErrNotIPv4
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return p, ErrTruncated
	}
	total := int(binary.BigEndian.Uint16(b[2:]))
	if total < ihl || total > len(b) {
		// Some senders pad; tolerate a total length that is short of the
		// buffer, but never one that claims more than we have.
		if total > len(b) {
			return p, ErrTruncated
		}
	}
	// Fragment offset non-zero, or MF set: we do not reassemble.
	if flags := binary.BigEndian.Uint16(b[6:]); flags&0x1fff != 0 || flags&0x2000 != 0 {
		return p, ErrFragmented
	}
	p.TTL = b[8]
	p.Proto = b[9]
	p.ID = binary.BigEndian.Uint16(b[4:])
	p.Src = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	p.Dst = netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]})
	p.Payload = b[ihl:total]
	return p, nil
}

// udpDatagram is a parsed UDP header over IPv4.
type udpDatagram struct {
	Src, Dst netip.AddrPort
	Data     []byte
}

func parseUDP(p ipv4) (udpDatagram, error) {
	var d udpDatagram
	if p.Proto != protoUDP {
		return d, fmt.Errorf("concentrator: IP proto %d is not UDP", p.Proto)
	}
	b := p.Payload
	if len(b) < 8 {
		return d, ErrTruncated
	}
	ln := int(binary.BigEndian.Uint16(b[4:]))
	if ln < 8 || ln > len(b) {
		ln = len(b) // tolerate a bad length rather than dropping the packet
	}
	d.Src = netip.AddrPortFrom(p.Src, binary.BigEndian.Uint16(b[0:]))
	d.Dst = netip.AddrPortFrom(p.Dst, binary.BigEndian.Uint16(b[2:]))
	d.Data = b[8:ln]
	return d, nil
}

// buildUDPPacket assembles a complete IPv4+UDP packet, which is what the client
// expects to write straight to tun0. Both checksums are computed: the client
// hands the bytes to the kernel, which will drop a packet with a bad IP header
// checksum.
func buildUDPPacket(src, dst netip.AddrPort, id uint16, ttl uint8, data []byte) []byte {
	total := 20 + 8 + len(data)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	binary.BigEndian.PutUint16(b[4:], id)
	if ttl == 0 {
		ttl = 64
	}
	b[8] = ttl
	b[9] = protoUDP
	sa, da := src.Addr().As4(), dst.Addr().As4()
	copy(b[12:16], sa[:])
	copy(b[16:20], da[:])
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20]))

	u := b[20:]
	binary.BigEndian.PutUint16(u[0:], src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(data)))
	copy(u[8:], data)
	binary.BigEndian.PutUint16(u[6:], udpChecksum(sa, da, u))
	return b
}

// checksum is the standard one's-complement Internet checksum.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// udpChecksum computes the UDP checksum including the IPv4 pseudo-header.
// udp must have its checksum field already zeroed.
func udpChecksum(src, dst [4]byte, udp []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src[:])
	add(dst[:])
	sum += uint32(protoUDP)
	sum += uint32(len(udp))
	add(udp)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	c := ^uint16(sum)
	if c == 0 {
		// 0 means "no checksum" in UDP, so the all-ones form is used instead.
		c = 0xffff
	}
	return c
}
