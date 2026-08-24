#!/bin/sh
#
# Stands up just enough of an MU5252 for the real zte_icg_agg to run, then
# execs it. Everything here mirrors something the device does at boot, and is
# commented with what that is.
set -eu

AGG=${AGG:-/opt/icg/zte_icg_agg}
SERVER_IP=${SERVER_IP:-172.17.0.1}      # the concentrator, seen from the container
TCP_PORT=${TCP_PORT:-10088}
UDP_BASE=${UDP_BASE:-10000}
WANS=${WANS:-eth0}                      # eth0 is in icg.conf AggNetcard and has a real path
LAN=${LAN:-br-lan}
TRACE=${TRACE:-0}

say() { printf '\033[36m[emu]\033[0m %s\n' "$*"; }

[ -x "$AGG" ] || {
  echo "no zte_icg_agg at $AGG — mount it, e.g." >&2
  echo "  docker run -v /path/to/zte_icg_agg:/opt/icg/zte_icg_agg:ro ..." >&2
  exit 2
}

# ---------------------------------------------------------------------------
# icg.conf: the device's own file, with the server details filled in. This is
# the whole hook that makes self-hosting possible — ForceUsingLocalInfo=1 makes
# the data plane read [ServerInfo] locally and never contact ZTE's MQTT broker.
# ---------------------------------------------------------------------------
sed -i \
  -e "s|__SERVER_IP__|$SERVER_IP|g" \
  -e "s|__TCP_PORT__|$TCP_PORT|g" \
  -e "s|__UDP_BASE__|$UDP_BASE|g" \
  /home/icg/icg.conf
say "concentrator: $SERVER_IP tcp/$TCP_PORT udp/$UDP_BASE+"

# ---------------------------------------------------------------------------
# WAN interfaces.
#
# The device binds each tunnel leg to a named netcard with SO_BINDTODEVICE, and
# before it will use one, is_wan_running() does ioctl(SIOCGIFFLAGS) and tests
# bit 6 — IFF_RUNNING. That is the detail that matters here: a `dummy` link
# never sets IFF_RUNNING, because it has no carrier. Addressing one and marking
# it up is not enough; the device correctly concludes the card is not there,
# reports "get wan change type:0" for every slot, creates no tunnel, and its
# handshake then has nothing to send on. That cost several runs to find.
#
# So: an interface that already exists (eth0, which icg.conf's AggNetcard
# happens to list) is used as-is — it has a carrier and a real route to the
# concentrator, which SO_BINDTODEVICE needs. Anything else is created as a veth
# pair rather than a dummy, so it at least reports IFF_RUNNING; note that such a
# leg can carry no traffic, since its peer is a dead end. Use it to exercise
# multi-card logic, not to move packets.
# ---------------------------------------------------------------------------
n=0
for w in $WANS; do
  n=$((n + 1))
  if ip link show "$w" >/dev/null 2>&1; then
    gw=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
    ip=$(ip -4 -o addr show dev "$w" 2>/dev/null | awk '{print $4}' | head -1)
    say "wan $w = ${ip:-none} via ${gw:-none} (pre-existing, real path)"
  else
    # veth, not dummy: veth gets a carrier once both ends are up, so
    # IFF_RUNNING is set and the device will consider the card present.
    ip link add "$w" type veth peer name "${w}p" 2>/dev/null || true
    ip addr add "10.90.$n.2/24" dev "$w" 2>/dev/null || true
    ip link set "${w}p" up 2>/dev/null || true
    ip link set "$w" up
    gw="10.90.$n.1"
    say "wan $w = 10.90.$n.2/24 via $gw (veth, no real path)"
  fi
  # The device learns each WAN's gateway from a per-interface dhcp lease file.
  printf 'export GATEWAY=%s\n' "${gw:-10.90.$n.1}" > "/tmp/ipv4config.$w"

  # IFF_RUNNING is the gate. Say so plainly if it is missing.
  if ! ip link show "$w" 2>/dev/null | grep -q 'LOWER_UP'; then
    say "  WARNING: $w has no carrier (no IFF_RUNNING) — the device will ignore it"
  fi
done

# Same shape, under the names the device's own scripts use.
cp /tmp/ipv4config.rmnet_data0 /tmp/ipv4config.zte_wan   2>/dev/null || true
cp /tmp/ipv4config.V3E1net0    /tmp/ipv4config.zte_mwan2 2>/dev/null || true
cp /tmp/ipv4config.V3E2net0    /tmp/ipv4config.zte_mwan3 2>/dev/null || true

# A LAN bridge for the transparent proxy's DNAT rule to attach to.
ip link add "$LAN" type bridge 2>/dev/null || true
ip addr add 192.168.0.1/24 dev "$LAN" 2>/dev/null || true
ip link set "$LAN" up

# rt_tables: the device ships named routing tables and its scripts reference
# them by name, so `ip route ... table usb0_RT` has to resolve.
mkdir -p /etc/iproute2
if ! grep -q usb0_RT /etc/iproute2/rt_tables 2>/dev/null; then
  for i in 0 1 2 3; do echo "$((100 + i)) usb${i}_RT"; done >> /etc/iproute2/rt_tables
  echo "110 tun0_RT" >> /etc/iproute2/rt_tables
fi

# tun0 is not optional. The device creates it before anything else and exits if
# it cannot ("[TUN] create tun/tap device tun0 failed"), so fail here with a
# useful message instead of letting the binary die opaquely.
if [ ! -c /dev/net/tun ]; then
  say "FATAL: /dev/net/tun is missing, and zte_icg_agg exits without it."
  say "       docker run needs: --device /dev/net/tun --cap-add NET_ADMIN"
  say "       (on a host that lacks it: sudo modprobe tun)"
  exit 3
fi

# Blackhole the DNS servers the device probes at startup, so the probe fails
# immediately rather than waiting on packets that will never come back. The
# ping wrapper in /usr/local/bin also caps the deadline; this is belt and
# braces, and it makes the failure instant instead of merely bounded.
for dns in 223.5.5.5 223.6.6.6 180.76.76.76 114.114.114.114 119.29.29.29; do
  ip route add blackhole "$dns" 2>/dev/null || true
done

# Loosen the same sysctls the device's own startup does.
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null || true
sysctl -qw net.ipv4.conf.all.route_localnet=1 2>/dev/null || true

say "uci store:"
sed -n 's/^\([a-z].*\)$/    \1/p' /etc/zteshim/uci.conf

say "running $(basename "$AGG") — press ctrl-c to stop"
echo "--------------------------------------------------------------------"

if [ "$TRACE" = 1 ]; then
  exec strace -f -e trace=network,openat -s 200 "$AGG" "$@"
fi
exec "$AGG" "$@"
