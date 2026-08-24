#!/usr/bin/env bash
#
# Deploy icgd — the self-hosted ICG concentrator — to a Linux server.
#
# Handles the two cases that actually come up:
#   * clean install on a fresh box: service account, dirs, config, systemd
#     unit, enable, health-check
#   * update of an existing install: replace the binary, keep the config,
#     restart, health-check, and roll back to the previous binary if it fails
#
# Ubuntu, Debian and Amazon Linux (anything with systemd, really). icgd is a
# static Go binary, so nothing is installed on the server: no Go, no runtime,
# no packages. This script builds locally and copies the result over.
#
#   ./deploy/icgd-deploy.sh root@concentrator.example.com
#   ./deploy/icgd-deploy.sh --allow 10.0.0.0/8 ubuntu@1.2.3.4
#   ./deploy/icgd-deploy.sh --dry-run ubuntu@1.2.3.4      # look, do not touch
#   ./deploy/icgd-deploy.sh --uninstall ubuntu@1.2.3.4
#
# The server-side half lives in deploy/icgd-install.sh, uploaded and run by
# this script. Read it first if you like; it is POSIX sh and takes its
# configuration from environment variables, so you can also run it by hand on
# a box you cannot reach from your laptop.
#
# Then see docs/OPERATING.md for how to point a
# device at the concentrator, and why doing that carelessly cuts the device's
# LAN off.
#
# SECURITY: ICG has no encryption and no authentication beyond a 4-byte magic
# that is a configuration constant. Anyone who can reach these ports can open a
# session and use the concentrator as an open proxy. This script therefore does
# not open a single firewall port unless you pass --open-firewall.

set -euo pipefail

TARGET=""
ARCH=""                       # detected from the server when empty
TCP_PORT=10088
UDP_BASE=10000
UDP_LEGS=4
MAGIC=12345678                # icg.conf TunnelIdentifier, hex
ALLOW=""                      # empty = proxied traffic may go anywhere
DENY="127.0.0.0/8,169.254.0.0/16,::1/128"
STATS=30s
DEVICES=""
HTTP_ADDR=""
HTTP_KEY=""
SERVICE_VERBOSE=0
OPEN_FIREWALL=0
DRY_RUN=0
FORCE_INSTALL=0
UNINSTALL=0
SSH_OPTS=""
CONFIG_FLAGS_GIVEN=0

ENV_FILE=/etc/icgd/icgd.env
LIB_DIR=/usr/local/lib/icgd
STAGED=/tmp/icgd.staged
INSTALLER_REMOTE=/tmp/icgd-install.sh

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarn:\033[0m %s\n' "$*" >&2; }

usage() {
    sed -n '3,32p' "$0" | sed 's/^#\( \|$\)//'
    cat <<'EOF'
Options:
  --arch amd64|arm64     target architecture (default: detected over ssh)
  --tcp-port N           TCP tunnel port            (default 10088)
  --udp-base N           first UDP tunnel port      (default 10000)
  --udp-legs N           number of UDP tunnel ports (default 4)
  --magic HEX            icg.conf TunnelIdentifier  (default 12345678)
  --allow CIDR[,CIDR]    where proxied traffic may go (default: anywhere)
  --deny  CIDR[,CIDR]    where it may never go
  --stats DURATION       per-session stats logging interval (0 disables)
  --devices MAC[,MAC]    only admit these device MACs. Admission control against
                         scanners, NOT authentication: the MAC arrives in an
                         unsigned plaintext handshake. Strongly advised if the
                         concentrator is reachable from the internet.
  --http ADDR            observability API/UI address. icgd defaults to
                         127.0.0.1:10099; pass "" here to keep that, or set an
                         address explicitly. Keep it on loopback and reach it
                         over an ssh tunnel unless you have a reason not to.
  --http-key KEY         shared secret for the observability API. Omitted means
                         icgd generates one and logs it at startup.
  --service-verbose      run the service with -v (debug logging)
  --open-firewall        opt in to opening the ports in ufw/firewalld
  --force-install        rewrite the config even if this is an update
  --uninstall            stop, disable and remove icgd
  --ssh-opts "..."       extra options passed to ssh and scp
  --dry-run              print what would happen, change nothing
  -h, --help             this

Passing any of --tcp-port/--udp-base/--udp-legs/--magic/--allow/--deny/--stats/
--service-verbose means "I want the config changed". An update that passes none
of them leaves /etc/icgd/icgd.env exactly as it was, so you can ship a new
binary without disturbing a working configuration.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --arch)             ARCH="$2"; shift 2 ;;
        --tcp-port)         TCP_PORT="$2"; CONFIG_FLAGS_GIVEN=1; shift 2 ;;
        --udp-base)         UDP_BASE="$2"; CONFIG_FLAGS_GIVEN=1; shift 2 ;;
        --udp-legs)         UDP_LEGS="$2"; CONFIG_FLAGS_GIVEN=1; shift 2 ;;
        --magic)            MAGIC="$2";    CONFIG_FLAGS_GIVEN=1; shift 2 ;;
        --allow)            ALLOW="$2";    CONFIG_FLAGS_GIVEN=1; shift 2 ;;
        --deny)             DENY="$2";     CONFIG_FLAGS_GIVEN=1; shift 2 ;;
        --stats)            STATS="$2";    CONFIG_FLAGS_GIVEN=1; shift 2 ;;
        --devices)          DEVICES="$2";  CONFIG_FLAGS_GIVEN=1; shift 2 ;;
        --http)             HTTP_ADDR="$2"; CONFIG_FLAGS_GIVEN=1; shift 2 ;;
        --http-key)         HTTP_KEY="$2";  CONFIG_FLAGS_GIVEN=1; shift 2 ;;
        --service-verbose)  SERVICE_VERBOSE=1; CONFIG_FLAGS_GIVEN=1; shift ;;
        --open-firewall)    OPEN_FIREWALL=1; shift ;;
        --force-install)    FORCE_INSTALL=1; shift ;;
        --uninstall)        UNINSTALL=1; shift ;;
        --ssh-opts)         SSH_OPTS="$2"; shift 2 ;;
        --dry-run)          DRY_RUN=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        -*)                 die "unknown option $1 (try --help)" ;;
        *)  [ -z "$TARGET" ] || die "two targets given: $TARGET and $1"
            TARGET="$1"; shift ;;
    esac
done

[ -n "$TARGET" ] || { usage >&2; die "no target given, e.g. ubuntu@1.2.3.4"; }

case "$MAGIC" in
    ""|*[!0-9a-fA-F]*) die "--magic must be hex digits only (icg.conf parses TunnelIdentifier as hex)" ;;
esac
for n in "$TCP_PORT" "$UDP_BASE" "$UDP_LEGS"; do
    case "$n" in ""|*[!0-9]*) die "ports and leg counts must be numeric, got '$n'" ;; esac
done
[ "$UDP_LEGS" -ge 1 ] || die "--udp-legs must be at least 1"
[ "$TCP_PORT" -le 65535 ] && [ "$((UDP_BASE + UDP_LEGS - 1))" -le 65535 ] \
    || die "the port range does not fit under 65535"

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
INSTALLER="$REPO_ROOT/deploy/icgd-install.sh"
[ -f "$REPO_ROOT/go.mod" ] || die "cannot find the repo root from $0"
[ -f "$INSTALLER" ] || die "missing $INSTALLER"

# shellcheck disable=SC2086  # SSH_OPTS is meant to be word-split
SSH() { ssh $SSH_OPTS -o BatchMode=yes -o ConnectTimeout=15 "$TARGET" "$@"; }
# shellcheck disable=SC2086
SCP() { scp -q $SSH_OPTS -o BatchMode=yes -o ConnectTimeout=15 "$1" "$TARGET:$2"; }

# ---------------------------------------------------------------------------
# probe: one round trip, reads nothing it does not need, changes nothing
# ---------------------------------------------------------------------------

info "probing $TARGET"
PROBE=$(SSH 'sh -s' <<'REMOTE'
set -u
. /etc/os-release 2>/dev/null || true
echo "ID=${ID:-unknown}"
echo "PRETTY=${PRETTY_NAME:-unknown}"
echo "MACHINE=$(uname -m)"
command -v systemctl >/dev/null 2>&1 && echo "SYSTEMD=yes" || echo "SYSTEMD=no"
[ "$(id -u)" = 0 ] && echo "AMROOT=yes" || echo "AMROOT=no"
command -v sudo >/dev/null 2>&1 && echo "HASSUDO=yes" || echo "HASSUDO=no"

# /etc/icgd is 0750 root:root, so an unprivileged probe cannot even stat what
# is inside it. Reading it without privilege reports "no config" on a server
# that has one, which would then silently overwrite a working config on every
# update. So escalate for the reads that need it.
if [ "$(id -u)" = 0 ]; then
    AS=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    AS="sudo -n"
else
    AS=""
    echo "PROBEPRIV=no"
fi

if [ -x /usr/local/bin/icgd ] && $AS test -f /etc/systemd/system/icgd.service; then
    echo "INSTALLED=yes"
else
    echo "INSTALLED=no"
fi
if $AS test -f /etc/icgd/icgd.env; then
    echo "HASENV=yes"
    $AS sed -n 's/^ICGD_ARGS=//p' /etc/icgd/icgd.env | head -1 | sed 's/^/CURARGS=/'
else
    echo "HASENV=no"
fi
REMOTE
) || die "cannot reach $TARGET over ssh (BatchMode is on, so your key must already work)"

probe() { printf '%s\n' "$PROBE" | sed -n "s/^$1=//p" | head -1; }

OS_ID=$(probe ID)
OS_PRETTY=$(probe PRETTY)
MACHINE=$(probe MACHINE)
INSTALLED=$(probe INSTALLED)
HAS_ENV=$(probe HASENV)
CUR_ARGS=$(probe CURARGS)

info "server: $OS_PRETTY ($MACHINE)"
case "$OS_ID" in
    ubuntu|debian|amzn) ;;
    rhel|centos|almalinux|rocky|fedora)
        warn "'$OS_ID' is not one of the tested distros, but only systemd is required" ;;
    *)  warn "unrecognised distro '$OS_ID'; continuing because only systemd is required" ;;
esac
[ "$(probe SYSTEMD)" = yes ] || die "no systemctl on the server; only systemd hosts are supported"

if [ "$(probe AMROOT)" = yes ]; then
    SUDO=""
elif [ "$(probe HASSUDO)" = yes ]; then
    # -n so a password prompt fails fast instead of hanging on a closed stdin.
    SUDO="sudo -n"
else
    die "not root on the server and no sudo available"
fi

if [ -z "$ARCH" ]; then
    case "$MACHINE" in
        x86_64|amd64)  ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) die "unsupported machine '$MACHINE'; pass --arch amd64|arm64 to override" ;;
    esac
fi

if [ "$UNINSTALL" = 1 ]; then
    MODE=uninstall
elif [ "$INSTALLED" = yes ]; then
    MODE=update
else
    MODE=install
fi
info "mode: $MODE (target linux/$ARCH)"

if [ "$(probe PROBEPRIV)" = no ]; then
    # Without privilege the probe cannot read the existing config, so it cannot
    # honour "leave it alone". Say so rather than quietly overwriting it.
    warn "could not read the server's config without sudo; an update will rewrite it"
fi
if [ "$MODE" = update ] && [ "$INSTALLED" = yes ] && [ "$HAS_ENV" = no ]; then
    warn "icgd is installed but /etc/icgd/icgd.env is missing; the config will be rewritten"
    FORCE_INSTALL=1
fi

# ---------------------------------------------------------------------------
# the flags the service will run with
# ---------------------------------------------------------------------------

compose_args() {
    printf -- '-tcp :%s -udp-base %s -udp-legs %s -magic %s -deny %s -stats %s' \
        "$TCP_PORT" "$UDP_BASE" "$UDP_LEGS" "$MAGIC" "$DENY" "$STATS"
    [ -n "$ALLOW" ] && printf -- ' -allow %s' "$ALLOW"
    [ -n "$DEVICES" ] && printf -- ' -devices %s' "$DEVICES"
    [ -n "$HTTP_ADDR" ] && printf -- ' -http %s' "$HTTP_ADDR"
    [ -n "$HTTP_KEY" ] && printf -- ' -http-key %s' "$HTTP_KEY"
    [ "$SERVICE_VERBOSE" = 1 ] && printf -- ' -v'
    printf '\n'
}

WRITE_ENV=1
ARGS=$(compose_args)
if [ "$MODE" = uninstall ]; then
    :
elif [ "$MODE" = update ] && [ "$HAS_ENV" = yes ] \
   && [ "$CONFIG_FLAGS_GIVEN" = 0 ] && [ "$FORCE_INSTALL" = 0 ]; then
    WRITE_ENV=0
    ARGS="$CUR_ARGS"
    info "reusing the config already on the server: $ARGS"
else
    info "config: $ARGS"
    if [ "$MODE" = update ] && [ -n "$CUR_ARGS" ] && [ "$ARGS" != "$CUR_ARGS" ]; then
        # The config is replaced wholesale rather than merged, so say so: a
        # flag you did not pass goes back to its default, it does not keep
        # whatever the server had.
        warn "the config is being REPLACED, not merged. Anything you did not pass"
        warn "reverts to its default. Previously: $CUR_ARGS"
    fi
fi

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

BINARY=""
if [ "$MODE" != uninstall ]; then
    command -v go >/dev/null 2>&1 || die "go is not installed locally, and it is needed to cross-compile icgd"
    VERSION=$(cd "$REPO_ROOT" && git describe --tags --always --dirty 2>/dev/null || echo dev)
    BINARY="$REPO_ROOT/bin/icgd-linux-$ARCH"
    info "building icgd $VERSION for linux/$ARCH"
    BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    ( cd "$REPO_ROOT" && mkdir -p bin &&
      GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 \
      go build -trimpath \
        -ldflags "-s -w -X main.version=$VERSION -X main.buildTime=$BUILT" \
        -o "$BINARY" ./cmd/icgd )
    info "built $BINARY ($(du -h "$BINARY" | cut -f1))"
fi

# ---------------------------------------------------------------------------
# run it
# ---------------------------------------------------------------------------

# sq single-quotes a value so it survives the remote shell verbatim.
sq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

remote_env() {
    printf 'ICGD_MODE=%s ICGD_WRITE_ENV=%s ICGD_OPEN_FW=%s ICGD_STAGED=%s ICGD_SUDO=%s ICGD_ARGS=%s' \
        "$(sq "$MODE")" "$(sq "$WRITE_ENV")" "$(sq "$OPEN_FIREWALL")" \
        "$(sq "$STAGED")" "$(sq "$SUDO")" "$(sq "$ARGS")"
}

if [ "$DRY_RUN" = 1 ]; then
    info "dry run — nothing was changed on $TARGET"
    echo
    echo "  would copy   $INSTALLER -> $TARGET:$INSTALLER_REMOTE"
    [ -n "$BINARY" ] && echo "  would copy   $BINARY -> $TARGET:$STAGED"
    echo "  would run    $(remote_env) sh $INSTALLER_REMOTE"
    echo
    exit 0
fi

info "uploading the installer"
SCP "$INSTALLER" "$INSTALLER_REMOTE"
if [ "$MODE" != uninstall ]; then
    info "uploading the binary"
    SCP "$BINARY" "$STAGED"
fi

info "running the $MODE"
# The installer is invoked with an explicit `sh` so the remote login shell does
# not matter, and its stdout is passed through as the progress log.
SSH "$(remote_env) sh $INSTALLER_REMOTE; rc=\$?; rm -f $INSTALLER_REMOTE; exit \$rc" \
    || die "$MODE failed on $TARGET (see the output above; a failed update rolls itself back)"

# ---------------------------------------------------------------------------
# what next
# ---------------------------------------------------------------------------

if [ "$MODE" = uninstall ]; then
    info "icgd removed from $TARGET"
    exit 0
fi

HOST=${TARGET#*@}
EFF_TCP=$(printf '%s\n' "$ARGS" | sed -n 's/.*-tcp [^ ]*:\([0-9]*\).*/\1/p'); EFF_TCP=${EFF_TCP:-$TCP_PORT}
EFF_UDP=$(printf '%s\n' "$ARGS" | sed -n 's/.*-udp-base \([0-9]*\).*/\1/p'); EFF_UDP=${EFF_UDP:-$UDP_BASE}
EFF_LEGS=$(printf '%s\n' "$ARGS" | sed -n 's/.*-udp-legs \([0-9]*\).*/\1/p'); EFF_LEGS=${EFF_LEGS:-$UDP_LEGS}
EFF_LAST=$((EFF_UDP + EFF_LEGS - 1))

EFF_HTTP=$(printf '%s\n' "$ARGS" | sed -n 's/.*-http \([^ ]*\).*/\1/p')
EFF_HTTP=${EFF_HTTP:-127.0.0.1:10099}
HTTP_PORT=${EFF_HTTP##*:}

info "$MODE complete"
cat <<EOF

  version   ssh $TARGET '${SUDO:+sudo }icgd -version'
  logs      ssh $TARGET '${SUDO:+sudo }journalctl -u icgd -f'
  status    ssh $TARGET '${SUDO:+sudo }systemctl status icgd'
  config    $ENV_FILE on the server (edit, then: systemctl restart icgd)
  rollback  $LIB_DIR/icgd.prev holds the binary this replaced

The web UI shows live device state and, more usefully, a "recent problems" list
with a concrete fix for each — the device itself will tell you nothing when it
cannot agree with a self-hosted concentrator.

  api key   ssh $TARGET '${SUDO:+sudo }journalctl -u icgd | grep -m1 observability'
  tunnel    ssh $SSH_OPTS -N -L $HTTP_PORT:$EFF_HTTP $TARGET
  then      open http://127.0.0.1:$HTTP_PORT/

To point a device at it — read docs/OPERATING.md
first, and verify each uci key against the live config:

  # /home/icg/icg.conf
  ForceUsingLocalInfo=1
  [ServerInfo]
  AggregationServerIP=$HOST
  AggregationServerTcpPort=$EFF_TCP
  AggregationServerUdpStartPort=$EFF_UDP
  AggregationServerTunIP=172.16.25.18
  AggregationServerIcgId=1

EOF
warn "ICG has no encryption and no authentication. Anyone who can reach tcp/$EFF_TCP"
warn "or udp/$EFF_UDP-$EFF_LAST on $HOST can use this box as an open proxy. Restrict it at"
warn "the firewall, or with --allow, and never expose it to the internet unguarded."
echo
warn "Setting opms_wan_mode=SMULTIWAN on a device whose concentrator is unreachable"
warn "makes icg_agg_fw.sh drop all LAN traffic, by design. Have the revert ready."
