#!/bin/sh
#
# Server-side installer for icgd, the self-hosted ICG concentrator.
#
# Normally run for you by deploy/icgd-deploy.sh, which builds the binary,
# uploads it and invokes this. It is a separate file on purpose: you can read
# it before it runs, and run it by hand on a box you cannot ssh to from your
# laptop.
#
# POSIX sh. Needs systemd. Installs nothing else — icgd is a static binary.
#
# Driven entirely by environment variables:
#
#   ICGD_MODE       install | update | uninstall        (required)
#   ICGD_ARGS       the flags to run icgd with          (required unless uninstall)
#   ICGD_STAGED     path to the new binary              (default /tmp/icgd.staged)
#   ICGD_WRITE_ENV  1 to (re)write the config, 0 to leave it alone (default 1)
#   ICGD_OPEN_FW    1 to open the ports in ufw/firewalld (default 0)
#   ICGD_SUDO       command prefix for privilege, e.g. "sudo -n" (default: none)
#   ICGD_ROOT       path prefix for every install location (default: none).
#                   Only for testing this script against a throwaway tree.
#
# Examples:
#   ICGD_MODE=install ICGD_ARGS='-tcp :10088 -udp-base 10000 -udp-legs 4' \
#     ICGD_SUDO='sudo -n' sh deploy/icgd-install.sh
#   ICGD_MODE=uninstall ICGD_SUDO='sudo -n' sh deploy/icgd-install.sh

set -eu

MODE=${ICGD_MODE:?ICGD_MODE must be install, update or uninstall}
ARGS=${ICGD_ARGS:-}
STAGED=${ICGD_STAGED:-/tmp/icgd.staged}
WRITE_ENV=${ICGD_WRITE_ENV:-1}
OPEN_FW=${ICGD_OPEN_FW:-0}
SUDO=${ICGD_SUDO:-}

# ICGD_ROOT exists so this script can be exercised against a scratch tree
# instead of a real machine; in production it is empty.
R=${ICGD_ROOT:-}
BIN=$R/usr/local/bin/icgd
LIB=$R/usr/local/lib/icgd
ETC=$R/etc/icgd
ENVF=$ETC/icgd.env
UNIT=$R/etc/systemd/system/icgd.service
USR=icgd

say()  { printf '    %s\n' "$*"; }
fail() { printf 'install: %s\n' "$*" >&2; exit 1; }

command -v systemctl >/dev/null 2>&1 || fail "no systemctl; only systemd hosts are supported"

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------

if [ "$MODE" = uninstall ]; then
    $SUDO systemctl disable --now icgd 2>/dev/null || true
    $SUDO rm -f "$UNIT" "$UNIT.bak" "$BIN"
    $SUDO rm -rf "$LIB" "$ETC"
    $SUDO systemctl daemon-reload
    say "removed the binary, config, unit and rollback copy"
    # The service account is deliberately left in place: deleting users
    # surprises people, and an unused nologin account costs nothing.
    say "the '$USR' account was left alone; 'userdel $USR' if you want it gone"
    exit 0
fi

case "$MODE" in
    install|update) ;;
    *) fail "ICGD_MODE must be install, update or uninstall (got '$MODE')" ;;
esac
[ -n "$ARGS" ] || fail "ICGD_ARGS is empty"
[ -f "$STAGED" ] || fail "no staged binary at $STAGED"

# Ports come out of ARGS so that an update which reuses the existing config
# still knows what to health-check and what to open in the firewall.
tcp_port=$(printf '%s\n' "$ARGS" | sed -n 's/.*-tcp [^ ]*:\([0-9]\{1,\}\).*/\1/p')
udp_base=$(printf '%s\n' "$ARGS" | sed -n 's/.*-udp-base \([0-9]\{1,\}\).*/\1/p')
udp_legs=$(printf '%s\n' "$ARGS" | sed -n 's/.*-udp-legs \([0-9]\{1,\}\).*/\1/p')
: "${tcp_port:=10088}" "${udp_base:=10000}" "${udp_legs:=4}"
udp_last=$((udp_base + udp_legs - 1))

# ---------------------------------------------------------------------------
# account and directories — idempotent
# ---------------------------------------------------------------------------

if ! id "$USR" >/dev/null 2>&1; then
    # --system is the Debian/Ubuntu spelling and also works on Amazon Linux
    # 2023; -r -M is the older RHEL-family spelling. Try both before giving up.
    $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin "$USR" 2>/dev/null \
      || $SUDO useradd -r -M -s /sbin/nologin "$USR" 2>/dev/null \
      || fail "could not create the '$USR' service account"
    say "created service account $USR"
fi
$SUDO install -d -m 0755 "$LIB" "$(dirname "$BIN")" "$(dirname "$UNIT")"
$SUDO install -d -m 0750 "$ETC"

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

if [ "$WRITE_ENV" = 1 ]; then
    if [ -f "$ENVF" ]; then
        $SUDO cp -p "$ENVF" "$ENVF.bak"
    fi
    {
        echo '# Managed by deploy/icgd-deploy.sh. Edit, then: systemctl restart icgd'
        echo '# Run "icgd -h" for the full flag list.'
        printf 'ICGD_ARGS=%s\n' "$ARGS"
    } | $SUDO tee "$ENVF" >/dev/null
    $SUDO chmod 0640 "$ENVF"
    say "wrote $ENVF"
else
    say "left $ENVF untouched"
fi

# ---------------------------------------------------------------------------
# systemd unit
# ---------------------------------------------------------------------------

# The service does not run as root, so a port below 1024 needs a capability.
caps=""
if [ "$tcp_port" -lt 1024 ] || [ "$udp_base" -lt 1024 ]; then
    caps="AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
fi

unit=$(cat <<UNITEOF
[Unit]
Description=ICG multi-WAN bonding concentrator (self-hosted)
Documentation=https://github.com/iangcarroll/zte-coord/blob/main/docs/PROTOCOL.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USR
Group=$USR
EnvironmentFile=${ENVF#"$R"}
# \$ICGD_ARGS is unquoted on purpose: systemd word-splits a bare \$VAR.
ExecStart=${BIN#"$R"} \$ICGD_ARGS
Restart=always
RestartSec=2

# ICG has no authentication, so assume this process is reachable by anyone who
# can reach its ports, and give it as little as possible.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
$caps
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNITEOF
)

if [ ! -f "$UNIT" ] || ! printf '%s\n' "$unit" | cmp -s - "$UNIT"; then
    if [ -f "$UNIT" ]; then
        $SUDO cp -p "$UNIT" "$UNIT.bak"
        say "unit changed; the previous one is at $UNIT.bak"
    fi
    printf '%s\n' "$unit" | $SUDO tee "$UNIT" >/dev/null
    $SUDO chmod 0644 "$UNIT"
    $SUDO systemctl daemon-reload
    say "wrote $UNIT"
else
    say "unit already current"
fi

# ---------------------------------------------------------------------------
# swap the binary, keeping the old one so a bad build can be undone
# ---------------------------------------------------------------------------

rollback=0
if [ -x "$BIN" ]; then
    $SUDO systemctl stop icgd 2>/dev/null || true
    $SUDO cp -p "$BIN" "$LIB/icgd.prev"
    rollback=1
fi
$SUDO install -m 0755 "$STAGED" "$BIN"
rm -f "$STAGED"
say "installed $BIN"

# ---------------------------------------------------------------------------
# start and verify
# ---------------------------------------------------------------------------

# listening: 0 = both ports bound, 1 = not bound, 2 = cannot tell
listening() {
    if command -v ss >/dev/null 2>&1; then
        ss -lntu 2>/dev/null | grep -qE "[:.]${tcp_port}[[:space:]]" || return 1
        ss -lntu 2>/dev/null | grep -qE "[:.]${udp_base}[[:space:]]" || return 1
        return 0
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -lntu 2>/dev/null | grep -qE "[:.]${tcp_port}[[:space:]]" || return 1
        netstat -lntu 2>/dev/null | grep -qE "[:.]${udp_base}[[:space:]]" || return 1
        return 0
    fi
    return 2
}

$SUDO systemctl enable icgd >/dev/null 2>&1 || true
$SUDO systemctl restart icgd

state=down
i=0
while [ "$i" -lt 20 ]; do
    if $SUDO systemctl is-active --quiet icgd; then
        # `|| rc=$?` keeps set -e out of it and preserves the real status.
        rc=0
        listening || rc=$?
        [ "$rc" = 0 ] && { state=up; break; }
        [ "$rc" = 2 ] && { state=unverified; break; }
    fi
    i=$((i + 1))
    sleep 1
done

if [ "$state" = down ]; then
    echo "--- icgd did not come up ---" >&2
    $SUDO systemctl status icgd --no-pager -l 2>&1 | tail -20 >&2 || true
    $SUDO journalctl -u icgd --no-pager -n 30 2>&1 >&2 || true
    if [ "$rollback" = 1 ] && [ -x "$LIB/icgd.prev" ]; then
        echo "--- rolling back to the previous binary ---" >&2
        $SUDO install -m 0755 "$LIB/icgd.prev" "$BIN"
        $SUDO systemctl restart icgd 2>/dev/null || true
        if $SUDO systemctl is-active --quiet icgd; then
            echo "rolled back: the previous version is running" >&2
        else
            echo "rollback failed too — icgd is DOWN" >&2
        fi
    fi
    exit 1
fi

if [ "$state" = unverified ]; then
    say "service is active (no ss or netstat here, so the ports were not verified)"
else
    say "service is active, listening on tcp/$tcp_port and udp/$udp_base-$udp_last"
fi

# ---------------------------------------------------------------------------
# firewall: report by default, act only when asked
# ---------------------------------------------------------------------------

if command -v ufw >/dev/null 2>&1; then fw=ufw
elif command -v firewall-cmd >/dev/null 2>&1; then fw=firewalld
else fw=none
fi

if [ "$OPEN_FW" != 1 ]; then
    case "$fw" in
        none) say "firewall: none detected" ;;
        *)    say "firewall: $fw is present and was NOT touched (pass --open-firewall)" ;;
    esac
    exit 0
fi

case "$fw" in
    ufw)
        $SUDO ufw allow "$tcp_port/tcp" >/dev/null
        j=0
        while [ "$j" -lt "$udp_legs" ]; do
            $SUDO ufw allow "$((udp_base + j))/udp" >/dev/null
            j=$((j + 1))
        done
        say "opened tcp/$tcp_port and udp/$udp_base-$udp_last in ufw"
        ;;
    firewalld)
        $SUDO firewall-cmd --permanent --add-port="$tcp_port/tcp" >/dev/null
        $SUDO firewall-cmd --permanent --add-port="$udp_base-$udp_last/udp" >/dev/null
        $SUDO firewall-cmd --reload >/dev/null
        say "opened tcp/$tcp_port and udp/$udp_base-$udp_last in firewalld"
        ;;
    none)
        say "asked to open the firewall, but neither ufw nor firewall-cmd is here"
        ;;
esac
