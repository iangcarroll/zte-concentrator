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
WANS=${WANS:-rmnet_data0 V3E1net0}      # icg.conf AggNetcard lists four; two is enough to stripe
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
# WAN interfaces. The device binds each tunnel leg to a specific netcard with
# SO_BINDTODEVICE, so the names have to match icg.conf's AggNetcard list. Dummy
# links give us that without any real radios; they all egress via the container's
# default route, so the "bonding" here is over one physical path — enough to
# exercise striping and reassembly, not to measure throughput.
# ---------------------------------------------------------------------------
n=0
for w in $WANS; do
  n=$((n + 1))
  ip link add "$w" type dummy 2>/dev/null || true
  ip addr add "10.90.$n.2/24" dev "$w" 2>/dev/null || true
  ip link set "$w" up
  # The device learns each WAN's gateway from a dhcp lease file per interface.
  printf 'export GATEWAY=10.90.%s.1\n' "$n" > "/tmp/ipv4config.$w"
  say "wan $w = 10.90.$n.2/24 via 10.90.$n.1"
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
