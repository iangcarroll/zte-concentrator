// Package icg implements ZTE's proprietary "ICG" (Intelligent Convergence
// Gateway) multi-WAN bonding protocol — the wire format spoken between a ZTE
// CPE's zte_icg_agg data plane and a cloud concentrator.
//
// The protocol was reverse-engineered from the MU5252's zte_icg_agg binary and
// a live capture; docs/PROTOCOL.md is the specification
// this package implements, and its section numbers are cited throughout.
//
// Everything here is transport-agnostic: the same framing runs over the TCP leg
// and over every UDP leg, in both directions. There is no cryptography and no
// frame checksum — the only thing resembling authentication is the 4-byte
// magic, which is a configuration value.
package icg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// DefaultMagic is icg.conf's TunnelIdentifier, which is parsed as HEX despite
// looking decimal ("TunnelIdentifier=12345678" -> 0x12345678).
const DefaultMagic uint32 = 0x12345678

// Header sizes. A frame is OuterLen + BodyLen(field) bytes on the wire; the
// body always begins with SubHdrLen bytes of per-packet metadata.
const (
	OuterLen  = 8  // magic + body_length
	SubHdrLen = 10 // icg_id + type + opcode + seq
	HdrLen    = OuterLen + SubHdrLen

	// MaxBodyLen bounds a single frame. The client clamps TCP MSS to 1400 and
	// reads at most 1400 bytes of stream data per frame, so anything much over
	// that is either corruption or a resync failure. Generous by 4x.
	MaxBodyLen = 8192
)

var (
	// ErrShort means the buffer does not yet hold a whole frame. It is not a
	// protocol error: on a stream the caller should read more.
	ErrShort = errors.New("icg: short buffer")
	// ErrMagic means the leading 4 bytes are not the configured magic, i.e.
	// framing is lost and the stream must be resynchronised.
	ErrMagic = errors.New("icg: bad magic")
	// ErrBodyLen means the declared body length is implausible.
	ErrBodyLen = errors.New("icg: bad body length")
)

// Frame is one ICG packet. See ICG_WIRE_PROTOCOL.md §2.
//
//	0x00 u32 LE  magic
//	0x04 u32 LE  body_length      (excludes these 8 bytes, includes the 10 below)
//	0x08 u32     icg_id           opaque; not validated by the client
//	0x0c u8      type
//	0x0d u8      opcode
//	0x0e u32 BE  seq              meaning depends on Type, see SeqMeaning
//	0x12 ...     payload
type Frame struct {
	Magic uint32

	// IcgID is stored and re-emitted verbatim, never validated.
	//
	// It carries icg.conf's AggregationServerIcgId — the identifier ZTE's MQTT
	// dispatch assigns to a CPE. PROVEN by experiment: setting
	// AggregationServerIcgId=305419896 (0x12345678) on the real binary made
	// every frame carry 0x12345678 here.
	//
	// This was previously documented as AggregationServerTunIP, the
	// concentrator's tun address. That reading fit the capture perfectly and
	// was still wrong: in the capture the id happened to equal the tun address
	// as an integer (0xac101912 == 172.16.25.18), because ZTE's dispatch
	// assigns the two consistently. Only running the binary with the two set
	// to different values separated them.
	//
	// The client writes it with htonl() and does not appear to compare it, so
	// we echo whatever the peer sent and never reject on it. (§2)
	IcgID  uint32
	Type   Type
	Opcode uint8
	Seq    uint32
	Body   []byte // payload only, i.e. without the 10-byte sub-header
}

// Len is the frame's total size on the wire.
func (f *Frame) Len() int { return HdrLen + len(f.Body) }

// AppendTo appends the encoded frame to dst and returns the extended slice.
func (f *Frame) AppendTo(dst []byte) []byte {
	magic := f.Magic
	if magic == 0 {
		magic = DefaultMagic
	}
	var hdr [HdrLen]byte
	binary.LittleEndian.PutUint32(hdr[0:], magic)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(SubHdrLen+len(f.Body)))
	binary.LittleEndian.PutUint32(hdr[8:], f.IcgID) // opaque: preserve bytes
	hdr[12] = byte(f.Type)
	hdr[13] = f.Opcode
	binary.BigEndian.PutUint32(hdr[14:], f.Seq)
	dst = append(dst, hdr[:]...)
	return append(dst, f.Body...)
}

// Encode returns the frame as a fresh byte slice.
func (f *Frame) Encode() []byte { return f.AppendTo(make([]byte, 0, f.Len())) }

// Decode parses one frame from the front of buf. It returns the frame and the
// number of bytes consumed. Body aliases buf — copy it if you retain the frame
// past the next read.
//
// magic of 0 means DefaultMagic.
func Decode(buf []byte, magic uint32) (*Frame, int, error) {
	if magic == 0 {
		magic = DefaultMagic
	}
	if len(buf) < OuterLen {
		return nil, 0, ErrShort
	}
	if binary.LittleEndian.Uint32(buf) != magic {
		return nil, 0, ErrMagic
	}
	bodyLen := int(binary.LittleEndian.Uint32(buf[4:]))
	if bodyLen < SubHdrLen || bodyLen > MaxBodyLen {
		return nil, 0, ErrBodyLen
	}
	if len(buf) < OuterLen+bodyLen {
		return nil, 0, ErrShort
	}
	b := buf[OuterLen : OuterLen+bodyLen]
	return &Frame{
		Magic:  magic,
		IcgID:  binary.LittleEndian.Uint32(b[0:]),
		Type:   Type(b[4]),
		Opcode: b[5],
		Seq:    binary.BigEndian.Uint32(b[6:]),
		Body:   b[SubHdrLen:],
	}, OuterLen + bodyLen, nil
}

func (f *Frame) String() string {
	return fmt.Sprintf("icg{%s/%s seq=%d body=%dB}", f.Type, OpcodeName(f.Type, f.Opcode), f.Seq, len(f.Body))
}

// IcgIDAsIP renders IcgID as a dotted quad. On a ZTE-dispatched device the id
// equals the tun address as an integer, so this is usually the readable form of
// it — but it is a convenience for logs, not a claim about the field. An id set
// by hand renders as nonsense here and that is fine.
func (f *Frame) IcgIDAsIP() net.IP {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], f.IcgID)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// A StreamReader deframes a byte stream (the TCP leg), resynchronising on the
// magic if framing is lost — which is what the client's own
// find_tcp_tunnel_header_again does. Frames may be concatenated inside one
// segment, and one frame may span segments.
type StreamReader struct {
	r     io.Reader
	magic uint32
	buf   []byte
	start int // first unconsumed byte
	end   int // one past the last valid byte

	// Resyncs counts how many times framing was lost and recovered. Non-zero
	// is a red flag worth surfacing: it means we and the client disagree about
	// message boundaries.
	Resyncs int

	// OnDesync, if set, is called the first time framing is lost, with up to
	// 16 bytes of what was actually on the wire.
	//
	// This exists because the device is the worst possible diagnostic partner:
	// pointed at a server it does not like, zte_icg_agg reports nothing useful
	// to its own operator. A magic (icg.conf TunnelIdentifier) mismatch would
	// otherwise look like "the tunnel just doesn't work", so the server has to
	// be the one that says what it saw.
	OnDesync func(prefix []byte)
}

// NewStreamReader wraps r. magic of 0 means DefaultMagic.
func NewStreamReader(r io.Reader, magic uint32) *StreamReader {
	if magic == 0 {
		magic = DefaultMagic
	}
	return &StreamReader{r: r, magic: magic, buf: make([]byte, 0, 2*MaxBodyLen)}
}

// Next returns the next frame. The returned Body aliases the reader's buffer
// and is invalidated by the following call to Next.
func (s *StreamReader) Next() (*Frame, error) {
	for {
		if s.end > s.start {
			f, n, err := Decode(s.buf[s.start:s.end], s.magic)
			switch {
			case err == nil:
				s.start += n
				return f, nil
			case errors.Is(err, ErrMagic), errors.Is(err, ErrBodyLen):
				if err := s.resync(); err != nil {
					return nil, err
				}
				continue
			}
			// ErrShort: fall through and read more.
		}
		if err := s.fill(); err != nil {
			return nil, err
		}
	}
}

// resync scans forward for the next plausible frame start. Returns an error
// only if the buffer has to be drained entirely, which the caller treats as
// "read more".
func (s *StreamReader) resync() error {
	if s.Resyncs == 0 && s.OnDesync != nil {
		end := min(s.start+16, s.end)
		s.OnDesync(append([]byte(nil), s.buf[s.start:end]...))
	}
	s.Resyncs++
	var want [4]byte
	binary.LittleEndian.PutUint32(want[:], s.magic)
	// Skip the byte we are on, then look for the magic.
	for i := s.start + 1; i+4 <= s.end; i++ {
		if s.buf[i] == want[0] && s.buf[i+1] == want[1] && s.buf[i+2] == want[2] && s.buf[i+3] == want[3] {
			s.start = i
			return nil
		}
	}
	// Keep the last 3 bytes: the magic may straddle the next read.
	keep := s.end - 3
	if keep < s.start {
		keep = s.start
	}
	s.start = keep
	return nil
}

func (s *StreamReader) fill() error {
	// Compact.
	if s.start > 0 {
		copy(s.buf, s.buf[s.start:s.end])
		s.end -= s.start
		s.start = 0
	}
	if s.end == cap(s.buf) {
		return fmt.Errorf("icg: frame exceeds %d bytes, giving up", cap(s.buf))
	}
	s.buf = s.buf[:cap(s.buf)]
	n, err := s.r.Read(s.buf[s.end:])
	s.end += n
	s.buf = s.buf[:s.end]
	if n == 0 && err != nil {
		return err
	}
	return nil
}
