// icgd is a self-hosted concentrator for ZTE's proprietary ICG multi-WAN
// bonding protocol. It lets a ZTE CPE (an MU5252, say) bond its WANs through
// infrastructure you control instead of ZTE's cloud in mainland China.
//
// This is research-grade software for a reverse-engineered protocol. See
// docs/PROTOCOL.md for the specification, and §12 of it
// for what is still guesswork.
//
// SECURITY: the ICG data plane has no cryptography and no authentication
// beyond a 4-byte magic that is a configuration constant, so anyone who can
// reach these ports can open a session and use the concentrator as an open
// proxy. Bind it to a private network, or put a firewall in front of it, or
// both. -allow restricts where proxied traffic may go.
//
// Pointing a device at it needs, on the device:
//
//	# /home/icg/icg.conf
//	ForceUsingLocalInfo=1        # read [ServerInfo] locally, never ask MQTT
//	[ServerInfo]
//	AggregationServerIP=<this host>
//	AggregationServerTcpPort=<-tcp port>
//	AggregationServerUdpStartPort=<-udp-base>
//	AggregationServerTunIP=172.16.25.18
//	AggregationServerIcgId=<any non-zero>
//
// plus the matching uci values under zwrt_router.icgmwan and
// zwrt_router.network.opms_wan_mode=SMULTIWAN. Read
// docs/OPERATING.md first: enabling SMULTIWAN with
// no reachable concentrator turns the device's LAN into a walled garden by
// design.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/iangcarroll/zte-coord/icg"
	"github.com/iangcarroll/zte-coord/icg/concentrator"
)

// Stamped by the linker; see the Makefile and deploy/icgd-deploy.sh. Knowing
// exactly what is running matters when the update path is "replace the binary".
var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	var (
		tcpAddr  = flag.String("tcp", ":10088", "TCP tunnel listen address (icg.conf AggregationServerTcpPort)")
		udpBase  = flag.Int("udp-base", 10000, "first UDP tunnel port (icg.conf AggregationServerUdpStartPort)")
		udpLegs  = flag.Int("udp-legs", 4, "number of consecutive UDP tunnel ports to open")
		magicStr = flag.String("magic", fmt.Sprintf("%x", icg.DefaultMagic),
			"icg.conf TunnelIdentifier, in HEX (the client parses it as hex too)")
		allow   = flag.String("allow", "", "comma-separated CIDRs proxied traffic may reach; empty means anywhere")
		deny    = flag.String("deny", "127.0.0.0/8,169.254.0.0/16,::1/128", "comma-separated CIDRs proxied traffic may never reach")
		verbose = flag.Bool("v", false, "debug logging")
		stats   = flag.Duration("stats", 30*time.Second, "how often to log per-session counters (0 to disable)")
		showVer = flag.Bool("version", false, "print the version and exit")
		devices = flag.String("devices", "", "device allowlist: comma-separated MACs, or @/path/to/file "+
			"(one MAC per line, # comments allowed). Empty admits any device.")
		httpAddr = flag.String("http", "127.0.0.1:10099",
			"observability API and web UI address; empty disables it. Loopback by "+
				"default — reach it with: ssh -N -L 10099:127.0.0.1:10099 user@server")
		httpKey = flag.String("http-key", "",
			"shared secret for the observability API. Empty generates one and prints it. "+
				"@/path/to/file reads it from a file.")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("icgd %s (built %s)\n", version, buildTime)
		return
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	magic, err := strconv.ParseUint(*magicStr, 16, 32)
	if err != nil {
		fatal(log, "bad -magic: %v (it is hex, e.g. 12345678)", err)
	}

	guard, err := newEgressGuard(*allow, *deny)
	if err != nil {
		fatal(log, "%v", err)
	}

	allowed, err := loadDevices(*devices)
	if err != nil {
		fatal(log, "-devices: %v", err)
	}

	cfg := concentrator.Config{
		Version:        version,
		AllowedDevices: allowed,
		TCPAddr:        *tcpAddr,
		UDPBase:        *udpBase,
		UDPLegs:        *udpLegs,
		Magic:          uint32(magic),
		Logger:         log,
		DialContextTCP: guard.dial,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := concentrator.New(cfg)

	secret, err := readSecret(*httpKey)
	if err != nil {
		fatal(log, "-http-key: %v", err)
	}
	obs, err := concentrator.NewHTTP(srv, concentrator.HTTPConfig{Addr: *httpAddr, Key: secret})
	if err != nil {
		fatal(log, "%v", err)
	}
	if obs != nil {
		go func() {
			<-ctx.Done()
			obs.Close()
		}()
		go func() {
			if err := obs.Serve(); err != nil {
				log.Error("observability server stopped", "err", err)
			}
		}()
		// Print the key where an operator will actually see it. If we
		// generated it, this is the only place it exists.
		banner := "observability UI: http://" + *httpAddr + "/"
		if secret == "" {
			log.Info(banner, "key", obs.GeneratedKey(),
				"note", "generated key, printed once; set -http-key to pin it")
		} else {
			log.Info(banner, "key", "(from -http-key)")
		}
	}

	if *stats > 0 {
		go logStats(ctx, log, srv, *stats)
	}

	admission := "any device"
	if len(allowed) > 0 {
		admission = fmt.Sprintf("%d allowed device(s)", len(allowed))
	}
	log.Info("icgd starting",
		"version", version, "built", buildTime,
		"magic", fmt.Sprintf("%#x", magic),
		"admission", admission,
		"note", "ICG has no encryption and no authentication; -devices is admission "+
			"control against scanners, not a security boundary")

	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fatal(log, "run: %v", err)
	}
	log.Info("icgd stopped")
}

func fatal(log *slog.Logger, format string, args ...any) {
	log.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

func logStats(ctx context.Context, log *slog.Logger, srv *concentrator.Server, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sessions := srv.Sessions()
			if len(sessions) == 0 {
				log.Info("no sessions")
				continue
			}
			for _, s := range sessions {
				// Per-session counters are logged by the session itself; this
				// is just the roll-call.
				log.Info("session", "tun_ip", s.TunIP(),
					"idle", s.IdleFor().Round(time.Millisecond),
					"dropped", s.Dropped())
			}
		}
	}
}

// loadDevices parses the -devices allowlist: either an inline comma-separated
// list, or @path to read one MAC per line.
//
// The MAC comes out of an unsigned plaintext handshake, so this stops noise and
// misconfiguration, not a determined attacker who knows a valid MAC.
func loadDevices(spec string) (map[string]bool, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var raw []string
	if after, ok := strings.CutPrefix(spec, "@"); ok {
		b, err := os.ReadFile(after)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			if line = strings.TrimSpace(line); line != "" {
				raw = append(raw, line)
			}
		}
	} else {
		raw = strings.Split(spec, ",")
	}
	out := map[string]bool{}
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		hw, err := net.ParseMAC(r)
		if err != nil {
			return nil, fmt.Errorf("%q is not a MAC address: %w", r, err)
		}
		out[strings.ToLower(hw.String())] = true
	}
	if len(out) == 0 {
		return nil, errors.New("no usable MAC addresses found")
	}
	return out, nil
}

// readSecret resolves -http-key, which may be a literal or @path.
func readSecret(spec string) (string, error) {
	if after, ok := strings.CutPrefix(spec, "@"); ok {
		b, err := os.ReadFile(after)
		if err != nil {
			return "", err
		}
		key := strings.TrimSpace(string(b))
		if key == "" {
			return "", fmt.Errorf("%s is empty", after)
		}
		return key, nil
	}
	return strings.TrimSpace(spec), nil
}

// egressGuard decides where proxied traffic may go. Without it a concentrator
// is an open proxy for anything that can reach its listener — and since the
// protocol has no authentication, that is anything on the network.
type egressGuard struct {
	allow, deny []netip.Prefix
	dialer      *net.Dialer
}

func newEgressGuard(allowCSV, denyCSV string) (*egressGuard, error) {
	g := &egressGuard{dialer: &net.Dialer{Timeout: 10 * time.Second}}
	var err error
	if g.allow, err = parsePrefixes(allowCSV); err != nil {
		return nil, fmt.Errorf("bad -allow: %w", err)
	}
	if g.deny, err = parsePrefixes(denyCSV); err != nil {
		return nil, fmt.Errorf("bad -deny: %w", err)
	}
	return g, nil
}

func parsePrefixes(csv string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range strings.Split(csv, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (g *egressGuard) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// The 5-tuple the client ships is numeric, so this should always parse;
	// refuse rather than resolve if it does not.
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("icgd: refusing non-literal destination %q", host)
	}
	for _, p := range g.deny {
		if p.Contains(ip) {
			return nil, fmt.Errorf("icgd: destination %s is denied", ip)
		}
	}
	if len(g.allow) > 0 {
		ok := false
		for _, p := range g.allow {
			if p.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("icgd: destination %s is not in -allow", ip)
		}
	}
	return g.dialer.DialContext(ctx, network, addr)
}
