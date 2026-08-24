// icg-probe validates an ICG concentrator by pretending to be a ZTE CPE.
//
// It speaks the real protocol — the real handshake, real WAN legs, real
// per-packet striping — so a pass here means the concentrator would work for a
// device, modulo the differences called out in
// docs/OPERATING.md.
//
//	icg-probe -server 1.2.3.4:10088 -udp 1.2.3.4:10000 -udp-legs 4 -legs 2 \
//	          -fetch http://example.com/
//
// Each check prints PASS or FAIL and the exit status is non-zero if any failed,
// so it is usable from a deploy script or CI.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/iangcarroll/zte-coord/icg"
	"github.com/iangcarroll/zte-coord/icg/client"
)

var (
	nPass, nFail, nSkip int
	verbose             bool
)

func main() {
	var (
		server   = flag.String("server", "", "concentrator TCP tunnel, host:port (required)")
		udpAddr  = flag.String("udp", "", "concentrator first UDP tunnel, host:port (empty skips the UDP checks)")
		tcpLegs  = flag.Int("legs", 2, "TCP tunnel legs to open, i.e. how many WANs to pretend to have")
		udpLegs  = flag.Int("udp-legs", 2, "UDP tunnel legs to open")
		magicStr = flag.String("magic", fmt.Sprintf("%x", icg.DefaultMagic), "TunnelIdentifier, hex")
		icgID    = flag.String("icg-id", "172.16.25.18", "AggregationServerIcgId, as a dotted quad — the session key")
		clientIP = flag.String("client-tun-ip", "172.16.25.19", "the device's own tun0 address")
		mac      = flag.String("mac", "02:00:5e:10:00:01", "device MAC, the identity the handshake carries")
		fetch    = flag.String("fetch", "", "fetch this http:// URL through the tunnel to prove the data path")
		timeout  = flag.Duration("timeout", 20*time.Second, "per-check timeout")
		verboseF = flag.Bool("v", false, "log every frame")
	)
	flag.Parse()
	verbose = *verboseF

	if *server == "" {
		fmt.Fprintln(os.Stderr, "-server is required, e.g. -server 1.2.3.4:10088")
		flag.Usage()
		os.Exit(2)
	}

	lvl := slog.LevelWarn
	if verbose {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	var magic uint32
	if _, err := fmt.Sscanf(*magicStr, "%x", &magic); err != nil {
		fatal("bad -magic %q: %v", *magicStr, err)
	}
	hw, err := net.ParseMAC(*mac)
	if err != nil {
		fatal("bad -mac: %v", err)
	}

	cfg := client.Config{
		TCPAddr:     *server,
		UDPAddr:     *udpAddr,
		TCPLegs:     *tcpLegs,
		UDPLegs:     *udpLegs,
		IcgID:       netip.MustParseAddr(*icgID),
		ClientTunIP: netip.MustParseAddr(*clientIP),
		MAC:         hw,
		Magic:       magic,
		Logger:      log,
	}

	fmt.Printf("icg-probe -> %s", *server)
	if *udpAddr != "" {
		fmt.Printf(" (+udp %s x%d)", *udpAddr, *udpLegs)
	}
	fmt.Printf("  tcp legs=%d  icg_id=%s  magic=%#x\n\n", *tcpLegs, *icgID, magic)

	c := client.New(cfg)
	if err := c.Dial(); err != nil {
		fail("connect", "%v", err)
		summary()
		os.Exit(1)
	}
	defer c.Close()
	pass("connect", "%d tcp leg(s)%s", len(c.Legs("tcp")), udpNote(c, *udpAddr))

	// --- handshake ---------------------------------------------------------
	t0 := time.Now()
	if err := c.Handshake(*timeout); err != nil {
		fail("handshake", "%v", err)
		summary()
		os.Exit(1)
	}
	pass("handshake", "ICG_SERVER_HANDSHAKE_ACK in %s, then ICG_CONFIRM_SERVER_ACK sent",
		time.Since(t0).Round(time.Millisecond))

	// --- keepalive is answered with a tunnel-detect probe -------------------
	// The concentrator also sends these unprompted at ~1 Hz per leg, so report
	// the absolute count: a delta can legitimately be zero if one was already
	// buffered when we started waiting.
	for _, l := range c.Legs("tcp") {
		if err := c.Keepalive(l); err != nil {
			fail("keepalive", "send on %s: %v", l, err)
		}
	}
	if _, err := c.WaitFor(*timeout, func(r client.Received) bool {
		return r.Frame.Type == icg.TypeAck && r.Frame.Opcode == icg.AckTunnelDetect
	}); err != nil {
		fail("keepalive", "no TUNNEL_DETECT came back: %v", err)
	} else {
		pass("keepalive", "TUNNEL_DETECT received (%d seen so far)", c.Stats.TunnelDetects.Load())
	}

	// --- UDP-leg RTT sync --------------------------------------------------
	if *udpAddr == "" || *udpLegs == 0 {
		skip("rtt-sync", "no -udp given")
	} else {
		okLegs := 0
		for i, l := range c.Legs("udp") {
			rtt, err := c.RTTSync(l, uint32(0x1000+i), *timeout)
			if err != nil {
				fail("rtt-sync", "%s: %v", l, err)
				continue
			}
			okLegs++
			if verbose {
				fmt.Printf("        %s rtt %s\n", l, rtt.Round(time.Millisecond))
			}
		}
		if okLegs > 0 {
			pass("rtt-sync", "%d/%d udp legs answered with our clock intact", okLegs, *udpLegs)
		}
	}

	// --- the data path -----------------------------------------------------
	if *fetch == "" {
		skip("data-path", "no -fetch URL given")
	} else {
		probeFetch(c, *fetch, *timeout)
	}

	// --- striping: one flow, frames deliberately out of order across legs --
	if *fetch != "" && *tcpLegs > 1 {
		probeStriping(c, *fetch, *timeout)
	} else if *tcpLegs <= 1 {
		skip("striping", "needs -legs 2 or more")
	}

	// --- cumulative ACKs ---------------------------------------------------
	if c.Stats.CumulativeAcks.Load() > 0 {
		pass("cumulative-ack", "%d received, so the device could free its send stash",
			c.Stats.CumulativeAcks.Load())
	} else {
		fail("cumulative-ack", "none received; a real device's retransmit stash would grow without bound")
	}

	if r := c.Stats.Resyncs.Load(); r > 0 {
		fail("framing", "%d stream resyncs — we and the concentrator disagree about frame boundaries", r)
	} else {
		pass("framing", "no stream resyncs")
	}

	summary()
	if nFail > 0 {
		os.Exit(1)
	}
}

// probeFetch does a real HTTP GET through the tunnel. This is the check that
// matters: it exercises the transparent proxy, the 5-tuple recovery, the
// upstream dial, both sequence spaces and the downlink framing at once.
func probeFetch(c *client.Client, raw string, timeout time.Duration) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		fail("data-path", "-fetch needs an http:// URL, got %q", raw)
		return
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	// The device ships the ORIGINAL destination, which it learned from
	// SO_ORIGINAL_DST, so resolve here exactly as the LAN client would have.
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		fail("data-path", "cannot resolve %s: %v", host, err)
		return
	}
	var v4 netip.Addr
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.To4()); ok && a.Is4() {
			v4 = a
			break
		}
	}
	if !v4.IsValid() {
		fail("data-path", "%s has no IPv4 address", host)
		return
	}
	var p uint16
	fmt.Sscanf(port, "%d", &p)
	server := netip.AddrPortFrom(v4, p)
	client := netip.MustParseAddrPort("192.168.0.245:54321")

	flow, err := c.OpenFlow(client, server)
	if err != nil {
		fail("data-path", "open flow: %v", err)
		return
	}
	path := u.RequestURI()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: icg-probe\r\nConnection: close\r\n\r\n", path, host)
	if err := flow.Write([]byte(req), 0); err != nil {
		fail("data-path", "write request: %v", err)
		return
	}

	body, err := c.CollectFlowData(flow.Tuple(), timeout, func(b []byte) bool {
		return bytes.Contains(b, []byte("\r\n\r\n"))
	})
	if err != nil {
		fail("data-path", "no HTTP response through the tunnel for %s: %v", server, err)
		fail2("the concentrator could not reach %s. Check that the URL's address is "+
			"routable FROM THE SERVER: the probe resolves the name locally and ships "+
			"the literal, so a DNS answer that differs (geo-DNS, IPv6-only, split "+
			"horizon) will fail here and look like a concentrator bug.", server)
		return
	}
	status, _, _ := strings.Cut(string(body), "\r\n")
	if !strings.HasPrefix(status, "HTTP/1.") {
		fail("data-path", "response does not look like HTTP: %.60q", string(body))
		return
	}
	if !strings.Contains(status, " 200 ") {
		// Anything else means our request reached the server mangled, which is
		// a concentrator bug, not a server response we should accept.
		fail("data-path", "GET %s -> %q; the request did not arrive intact", raw, status)
		return
	}
	pass("data-path", "GET %s [%s] -> %q (%d bytes through the tunnel)",
		raw, server, status, len(body))
	_ = flow.Close()
}

// probeStriping repeats the fetch with the request split into single bytes sent
// round-robin across every leg in REVERSE sequence order. If the concentrator's
// reassembly is wrong the upstream sees garbage and the HTTP response never
// arrives — which is exactly the bug that a settle window fixes.
func probeStriping(c *client.Client, raw string, timeout time.Duration) {
	u, _ := url.Parse(raw)
	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		skip("striping", "cannot resolve %s", host)
		return
	}
	var v4 netip.Addr
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.To4()); ok && a.Is4() {
			v4 = a
			break
		}
	}
	server := netip.AddrPortFrom(v4, 80)
	client := netip.MustParseAddrPort("192.168.0.246:54322")

	flow, err := c.OpenFlow(client, server)
	if err != nil {
		fail("striping", "open flow: %v", err)
		return
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: icg-probe-striped\r\nConnection: close\r\n\r\n",
		u.RequestURI(), host)

	// Chunk it, then hand the chunks over in an order no receiver would like:
	// last first, alternating legs. The sequence numbers still ascend in the
	// order they were allocated, so only reassembly can save this.
	const chunk = 7
	var chunks [][]byte
	for i := 0; i < len(req); i += chunk {
		end := min(i+chunk, len(req))
		chunks = append(chunks, []byte(req[i:end]))
	}
	// Allocate ascending sequence numbers first, then transmit back to front
	// across alternating legs. That is genuine reordering: the bytes are in
	// the right order, they just arrive in the wrong one, which is exactly
	// what per-packet striping across WANs of different latency produces.
	seqs := make([]uint32, len(chunks))
	for i := range chunks {
		seqs[i] = c.NextTCPSeq()
	}
	nLegs := len(c.Legs("tcp"))
	for i := len(chunks) - 1; i >= 0; i-- {
		if err := flow.WriteAt(seqs[i], chunks[i], i%nLegs); err != nil {
			fail("striping", "write chunk %d: %v", i, err)
			return
		}
	}

	body, err := c.CollectFlowData(flow.Tuple(), timeout, func(b []byte) bool {
		return bytes.Contains(b, []byte("\r\n\r\n"))
	})
	if err != nil {
		fail("striping", "reassembly failed: %v (%d bytes back)", err, len(body))
		return
	}
	status, _, _ := strings.Cut(string(body), "\r\n")
	if !strings.Contains(status, " 200 ") {
		fail("striping", "%d chunks sent in reverse across %d legs -> %q; reassembly is wrong",
			len(chunks), nLegs, status)
		return
	}
	pass("striping", "%d chunks reversed across %d legs, reassembled intact -> %q",
		len(chunks), nLegs, status)
	_ = flow.Close()
}

func udpNote(c *client.Client, udpAddr string) string {
	if udpAddr == "" {
		return ""
	}
	return fmt.Sprintf(", %d udp leg(s)", len(c.Legs("udp")))
}

func pass(name, format string, a ...any) {
	nPass++
	fmt.Printf("  \033[32mPASS\033[0m %-16s %s\n", name, fmt.Sprintf(format, a...))
}

// fail2 adds an explanatory line under a failure without counting again.
func fail2(format string, a ...any) {
	fmt.Printf("       %s\n", fmt.Sprintf(format, a...))
}

func fail(name, format string, a ...any) {
	nFail++
	fmt.Printf("  \033[31mFAIL\033[0m %-16s %s\n", name, fmt.Sprintf(format, a...))
}

func skip(name, format string, a ...any) {
	nSkip++
	fmt.Printf("  \033[33mSKIP\033[0m %-16s %s\n", name, fmt.Sprintf(format, a...))
}

func summary() {
	fmt.Printf("\n  %d passed, %d failed, %d skipped\n", nPass, nFail, nSkip)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "icg-probe: "+format+"\n", a...)
	os.Exit(2)
}
