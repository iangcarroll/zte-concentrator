#!/bin/sh
#
# End-to-end test: the device's REAL binary, carrying REAL traffic, through a
# concentrator built from this repo.
#
# A LAN client in its own network namespace makes an ordinary HTTP request. The
# device DNATs it into its transparent proxy, stripes it over the ICG tunnel,
# our concentrator recovers the original 5-tuple and proxies it to the internet,
# and the response comes back the same way. If this passes, the protocol reading
# is right — not merely self-consistent with a client we also wrote.
#
#   ./e2e.sh                      # build if needed, run, assert, clean up
#   KEEP=1 ./e2e.sh               # leave the containers up to poke at
#
# Needs docker, and the plaintext binary at blobs/zte_icg_agg (make decrypt).
set -eu

NET=${NET:-icg-e2e}
SUBNET=${SUBNET:-10.77.0.0/16}
SRV_IP=${SRV_IP:-10.77.0.10}
TCP_PORT=${TCP_PORT:-10088}
UDP_BASE=${UDP_BASE:-10000}
API_PORT=${API_PORT:-10099}
API_KEY=${API_KEY:-e2e-test-key}
IMAGE=${IMAGE:-zte-emu}
SRV_IMAGE=${SRV_IMAGE:-icgd-e2e}
BLOB=${BLOB:-blobs/zte_icg_agg}
# A public host to fetch. Resolved on the host and passed as a literal, because
# the LAN namespace has no resolver — only TCP is DNATed into the tunnel.
TARGET_HOST=${TARGET_HOST:-example.com}
DEADLINE=${DEADLINE:-60}
# How long to hold the tunnel open after the fetch. Must exceed 30s: that is
# when device_zombie_state_check releases resources if it thinks we have gone
# silent, and whether our 1 Hz traffic refreshes its activity timestamp is the
# single thing most likely to be wrong. 0 skips the soak.
SOAK=${SOAK:-40}

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; failed=1; }
failed=0

# Ask the concentrator itself what it saw. Run from a throwaway container on the
# same network so we do not need a published port or a JSON parser on the host.
api() {
  docker run --rm --network "$NET" alpine:3.20 \
    wget -q -O - --header="X-Icgd-Key: $API_KEY" "http://$SRV_IP:$API_PORT/api/status" 2>/dev/null
}
# jget <json> <key> — pull one numeric field out without a jq dependency.
# Prints 0 for anything that is not a plain integer, so callers can use [ -ge ]
# without set -e killing the run on a surprise.
jget() {
  # shellcheck disable=SC2020  # a character set is exactly what is wanted
  v=$(printf '%s' "$1" | tr ',{}[]' '\n\n\n\n\n' | grep "\"$2\":" | head -1 | sed 's/.*: *//;s/"//g;s/[^0-9].*$//')
  case "$v" in ''|*[!0-9]*) echo 0 ;; *) echo "$v" ;; esac
}

cleanup() {
  [ "${KEEP:-0}" = 1 ] && { say "KEEP=1, leaving $NET / icgd-e2e / icgdev-e2e up"; return; }
  docker rm -f icgdev-e2e icgd-e2e >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ -f "$here/$BLOB" ] || { echo "no $BLOB — run 'make decrypt' first" >&2; exit 2; }

# --- build both sides -------------------------------------------------------
say "building the concentrator for linux/arm64"
tmp=$(mktemp -d)
( cd "$root" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$tmp/icgd" ./cmd/icgd )
printf 'FROM alpine:3.20\nCOPY icgd /usr/local/bin/icgd\nENTRYPOINT ["/usr/local/bin/icgd"]\n' > "$tmp/Dockerfile"
docker build --platform linux/arm64 -q -t "$SRV_IMAGE" "$tmp" >/dev/null
rm -rf "$tmp"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  say "building the device harness image"
  docker build --platform linux/arm64 -q -t "$IMAGE" "$here" >/dev/null
fi

# --- bring both up on their own network ------------------------------------
cleanup
docker network create --subnet "$SUBNET" "$NET" >/dev/null
say "concentrator at $SRV_IP:$TCP_PORT"
docker run -d --name icgd-e2e --network "$NET" --ip "$SRV_IP" "$SRV_IMAGE" \
  -tcp ":$TCP_PORT" -udp-base "$UDP_BASE" -udp-legs 2 -v -stats 30s \
  -http "0.0.0.0:$API_PORT" -http-key "$API_KEY" >/dev/null

say "starting the device's own zte_icg_agg"
docker run -d --name icgdev-e2e --platform linux/arm64 --network "$NET" \
  --privileged --device /dev/net/tun \
  -e SERVER_IP="$SRV_IP" -e TCP_PORT="$TCP_PORT" -e UDP_BASE="$UDP_BASE" \
  -v "$here/$BLOB:/opt/icg/zte_icg_agg:ro" "$IMAGE" >/dev/null

# --- wait for the device to declare the tunnel up ---------------------------
say "waiting for the device to reach ICG_AND_SRV_BOTH_OK"
i=0
while [ "$i" -lt "$DEADLINE" ]; do
  if docker logs icgdev-e2e 2>&1 | grep -q 'icg_agg_status=\[1\]'; then break; fi
  if ! docker inspect -f '{{.State.Running}}' icgdev-e2e 2>/dev/null | grep -q true; then
    fail "the device container exited"
    docker logs icgdev-e2e 2>&1 | tail -30
    exit 1
  fi
  i=$((i + 1)); sleep 1
done

if docker logs icgdev-e2e 2>&1 | grep -q 'start send handshake with config'; then
  pass "device sent ICG_HANDSHAKE_REQ_WITH_CONFIG"
else fail "device never sent a handshake"; fi
if docker logs icgdev-e2e 2>&1 | grep -q 'update ICG_SERVER_READY'; then
  pass "device accepted our ICG_SERVER_HANDSHAKE_ACK"
else fail "device did not accept our ack"; fi
if docker logs icgdev-e2e 2>&1 | grep -q 'icg state ICG_AND_SRV_BOTH_OK'; then
  pass "device reached ICG_AND_SRV_BOTH_OK (after ${i}s)"
else fail "device never reached ICG_AND_SRV_BOTH_OK"; fi
if docker logs icgdev-e2e 2>&1 | grep -q 'icg_agg_status=\[1\]'; then
  pass "device set icg_agg_status=1 — it considers the tunnel up"
else fail "device never set icg_agg_status=1"; fi
if docker logs icgdev-e2e 2>&1 | grep -q 'agg_server_exit'; then
  fail "the device's zombie watchdog gave up on us"
fi
if docker logs icgd-e2e 2>&1 | grep -q 'handshake complete'; then
  pass "concentrator logged a completed handshake"
else fail "concentrator never completed a handshake"; fi
if docker logs icgd-e2e 2>&1 | grep -qE 'magic-mismatch|framing-lost'; then
  fail "concentrator reported a framing problem"
  docker logs icgd-e2e 2>&1 | grep -E 'magic-mismatch|framing-lost' | head -3
fi

[ "$failed" = 0 ] || { say "handshake failed; not attempting traffic"; exit 1; }

# --- real traffic -----------------------------------------------------------
# A LAN client has to be in its own namespace: the device's DNAT is in
# PREROUTING, which only sees packets ARRIVING on br-lan. Traffic generated
# inside the device's own namespace traverses OUTPUT and would bypass it.
say "wiring a LAN client into br-lan"
docker exec icgdev-e2e sh -c '
  set -e
  ip netns add lan 2>/dev/null || true
  ip link add lanveth type veth peer name lan0 2>/dev/null || true
  ip link set lanveth master br-lan up
  ip link set lan0 netns lan 2>/dev/null || true
  ip -n lan addr add 192.168.0.245/24 dev lan0 2>/dev/null || true
  ip -n lan link set lo up
  ip -n lan link set lan0 up
  ip -n lan route replace default via 192.168.0.1
  # The rule the device'"'"'s own icg_agg_fw.sh installs, which this harness
  # stubs out: redirect LAN TCP into the transparent proxy.
  iptables -t nat -C PREROUTING -i br-lan -p tcp -j DNAT --to-destination 172.16.25.18:14000 2>/dev/null \
    || iptables -t nat -A PREROUTING -i br-lan -p tcp -j DNAT --to-destination 172.16.25.18:14000
'

target_ip=$(getent ahostsv4 "$TARGET_HOST" 2>/dev/null | awk '{print $1; exit}')
[ -n "$target_ip" ] || target_ip=$(docker run --rm alpine:3.20 getent ahostsv4 "$TARGET_HOST" | awk '{print $1; exit}')
say "fetching http://$TARGET_HOST/ ($target_ip) from 192.168.0.245 through the tunnel"

if body=$(docker exec icgdev-e2e sh -c \
      "ip netns exec lan wget -q -O - -T 30 --header='Host: $TARGET_HOST' http://$target_ip/ 2>&1"); then
  if printf '%s' "$body" | grep -qi '</html>'; then
    pass "got $(printf '%s' "$body" | wc -c) bytes of HTML through the tunnel"
  else
    fail "response did not look like HTML: $(printf '%s' "$body" | head -c 120)"
  fi
else
  fail "the fetch failed"
  docker logs icgd-e2e 2>&1 | tail -20
fi

# The fetch succeeding is necessary but not sufficient evidence: assert the
# concentrator's own counters, so a response that somehow arrived by another
# path could not pass this test.
state=$(api)
if [ -z "$state" ]; then
  fail "could not read the concentrator API"
else
  total=$(jget "$state" tcp_total)
  skipped=$(jget "$state" tcp_skipped)
  late=$(jget "$state" tcp_late)
  refused=$(jget "$state" refused)
  if [ "${total:-0}" -ge 1 ]; then
    pass "concentrator proxied $total TCP flow(s)"
  else fail "concentrator proxied no TCP flows — the response did not come through the tunnel"; fi
  if [ "${skipped:-0}" = 0 ]; then
    pass "no reassembly gaps were skipped"
  else fail "reassembler skipped $skipped sequence(s) — data was lost"; fi
  if [ "${late:-0}" = 0 ]; then
    pass "no packets arrived too late to use"
  else fail "$late packet(s) arrived after their window closed"; fi
  [ "${refused:-0}" = 0 ] || fail "$refused frame(s) were refused by admission control"
fi

# --- liveness across the zombie threshold -----------------------------------
# device_zombie_state_check releases the tunnel after 30s of what it considers
# silence and stops the daemon after 150s. Sitting idle past 30s and then
# fetching again is the only way to find out whether our keepalives count.
if [ "$failed" = 0 ] && [ "${SOAK:-0}" -gt 0 ]; then
  say "holding the tunnel idle for ${SOAK}s to cross the 30s zombie threshold"
  sleep "$SOAK"

  if docker logs icgdev-e2e 2>&1 | grep -q 'agg_server_exit'; then
    fail "the device's zombie watchdog gave up on us during the soak"
  else pass "no zombie exit after ${SOAK}s"; fi
  if docker logs icgdev-e2e 2>&1 | grep -qi 'release.*resource\|zombie'; then
    fail "the device released tunnel resources during the soak"
    docker logs icgdev-e2e 2>&1 | grep -i 'release.*resource\|zombie' | tail -3
  else pass "the device did not release tunnel resources"; fi
  if docker logs icgdev-e2e 2>&1 | grep -q 'icg_agg_status = 0\|icg_agg_status=\[0\]'; then
    fail "the device took the tunnel back down during the soak"
  else pass "the device still considers the tunnel up"; fi

  # And it must still actually work, not merely still claim to.
  if docker exec icgdev-e2e sh -c \
        "ip netns exec lan wget -q -O - -T 30 --header='Host: $TARGET_HOST' http://$target_ip/ 2>&1" \
        | grep -qi '</html>'; then
    pass "a second fetch still works after ${SOAK}s idle"
  else fail "the tunnel stopped carrying traffic after ${SOAK}s idle"; fi

  state=$(api)
  total=$(jget "$state" tcp_total)
  if [ "${total:-0}" -ge 2 ]; then
    pass "concentrator proxied $total flows in total"
  else fail "the second flow never reached the concentrator"; fi
fi

echo
[ "$failed" = 0 ] && { say "all checks passed — the real device carried real traffic"; exit 0; }
say "some checks failed"; exit 1
