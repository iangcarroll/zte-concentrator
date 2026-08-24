# Running a concentrator

How to deploy `icgd`, configure it, watch it, and point a device at it.

Read [`STATUS.md`](STATUS.md) first if you want to know how much to trust this.
[`PROTOCOL.md`](PROTOCOL.md) is the wire specification.

---

## ⚠ Two things that will ruin your day

**The protocol has no authentication and no encryption.** None. The only thing
resembling a credential is a 4-byte "magic" that is a configuration constant
published in the device's own config file. Anyone who can reach the tunnel
ports can open a session and use your box as an open proxy, and everything
inside the tunnel is in the clear to anyone on the path. Treat an exposed
concentrator accordingly: restrict egress with `-allow`, restrict admission
with `-devices`, and put a firewall in front of it if you can.

**`SMULTIWAN` with an unreachable concentrator turns the device's LAN into a
walled garden, by design.** `icg_agg_fw.sh` installs a blanket
`iptables -A client_access_network -j DROP` when `AggregationServerTunIP` is
empty. Do not flip the mode on a device that is someone's only gateway without
a working concentrator and a tested revert to hand. The revert is
`uci set zwrt_router.network.opms_wan_mode=MULTIWAN`, commit, restore
networking.

---

Pointing a device at the concentrator you deploy here is a separate procedure:
see [`DEVICE-SETUP.md`](DEVICE-SETUP.md).

## Deploy

`deploy/icgd-deploy.sh` builds locally, uploads, and installs over ssh. It
works out **clean install versus update** by itself, from whether the binary
and unit already exist. Ubuntu, Debian and Amazon Linux are tested; anything
with systemd should work. `icgd` is a static binary, so nothing is installed on
the server — no Go, no runtime, no packages.

```sh
./deploy/icgd-deploy.sh --dry-run ubuntu@1.2.3.4          # look first
./deploy/icgd-deploy.sh --devices 02:00:5e:10:00:01 ubuntu@1.2.3.4
make deploy HOST=ubuntu@1.2.3.4 ARGS="--allow 10.0.0.0/8"
```

| behaviour | what happens |
|---|---|
| clean install | service account (nologin), `/etc/icgd/icgd.env`, a hardened systemd unit, enable, start, verify the ports are bound |
| update | replace the binary and restart. **The config is left exactly as it is** unless you pass a config flag, so shipping a new build cannot disturb a working setup |
| failed health check | the previous binary is restored from `/usr/local/lib/icgd/icgd.prev` and restarted, rather than leaving the box down |
| config change | replaced **wholesale**, not merged, with a loud warning. A flag you do not pass reverts to its default |
| firewall | never touched without `--open-firewall`. An open port on this protocol is an open proxy, so that has to be your decision |

`--ssh-opts` is passed to both `ssh` and `scp`, so use `-o Port=443` rather
than `-p 443` if you need a non-standard port (`scp -p` means something else).

The server-side half is `deploy/icgd-install.sh`: POSIX sh, driven entirely by
environment variables, and runnable by hand on a box you cannot reach from your
laptop. Read it before it runs as root if you like — that is why it is a
separate file.

Uninstall with `--uninstall`. The service account is deliberately left behind.

---

## Configure

Everything lives in `/etc/icgd/icgd.env` as one `ICGD_ARGS=` line. Edit it and
`systemctl restart icgd`, or re-run the deploy script with flags.

```
ICGD_ARGS=-tcp :10088 -udp-base 10000 -udp-legs 4 -magic 12345678 \
          -allow 0.0.0.0/0 -deny 127.0.0.0/8,169.254.0.0/16,::1/128 \
          -devices 02:00:5e:10:00:01 -stats 30s
```

| flag | what it does |
|---|---|
| `-tcp :10088` | the TCP tunnel port. The device takes this from `icg.conf AggregationServerTcpPort` |
| `-udp-base 10000` `-udp-legs 4` | UDP tunnel ports; WAN leg N connects to `base+N`. One per WAN, plus headroom |
| `-magic 12345678` | must equal the device's `icg.conf TunnelIdentifier`. **Parsed as hex**, despite looking decimal |
| `-allow` / `-deny` | CIDRs proxied traffic may and may not reach. Without `-allow`, anywhere |
| `-devices` | MAC allowlist; see below |
| `-http` / `-http-key` | the observability endpoint; see below |
| `-stats 30s` | how often each session logs its counters |
| `-v` | debug logging. The diagnostics below do **not** need it |

### Admission control

`-devices aa:bb:cc:dd:ee:ff,...` or `-devices @/etc/icgd/devices` (one MAC per
line, `#` comments) restricts which CPEs may open a session, matched against
the MAC in the handshake. An unlisted device gets **silence** — no
`ICG_SERVER_HANDSHAKE_ACK`, so it never leaves `ICG_INIT_STATE` — and every
non-handshake frame from it is dropped.

**This is not authentication.** The MAC arrives in an unsigned plaintext
handshake over a protocol with no cryptography, so anyone who knows a valid MAC
can present it. What it buys is that internet background noise and
misconfigured devices cannot open a session on a box that has to be exposed for
a device to reach it at all. Use it; do not rely on it.

---

## Watch it

```sh
icgd -version
systemctl status icgd
journalctl -u icgd -f
```

`-http` (default `127.0.0.1:10099`) serves a JSON API and a single
self-contained page — live device and per-leg state, the counters that indicate
data loss, and a list of recent problems. Auth is one shared secret, accepted
as `Authorization: Bearer`, `X-Icgd-Key:` or `?key=`, compared in constant
time. `icgd` generates one and logs it at startup unless `-http-key` pins it:

```sh
ssh SERVER 'sudo journalctl -u icgd | grep -m1 observability'   # get the key
ssh -N -L 10099:127.0.0.1:10099 SERVER                          # tunnel to it
open http://127.0.0.1:10099/
```

Loopback by default on purpose: the tunnel ports already have to be exposed, and
a second public surface should be a decision rather than an accident.

| endpoint | what it gives you |
|---|---|
| `/api/status` | everything — listeners, admission, every session, the notices |
| `/api/sessions` | just the devices |
| `/api/notices` | just the recent problems |

The counters worth watching are `reorder_skipped` and `late` (data was thrown
away), `dropped_in` (we could not keep up), `stash_misses` (a retransmit we
could not serve) and `upstream_dial_failures`.

---

## Diagnose a device that "just doesn't work"

This is the part that matters in practice. `zte_icg_agg` was written to talk to
ZTE's own cloud and reports essentially nothing useful to its operator when
pointed elsewhere: a wrong `TunnelIdentifier`, a refused device and an
unreachable upstream all look identical from the device's side, which is to say
they look like nothing at all.

So the concentrator explains instead. Every failure you can act on becomes a
**notice carrying the fix**, visible in the UI and at `/api/notices` without
`-v`. Repeats collapse into one entry with a count, so a device stuck in its
1 Hz retry loop cannot flush the list.

| notice | means | it tells you |
|---|---|---|
| `magic-mismatch` | the first four bytes were not our magic | the exact `TunnelIdentifier=` to set on the device, or the `-magic` to restart with |
| `magic-mismatch-udp` | same, on a UDP leg | same |
| `no-valid-frame` | a peer connected and left without one valid frame | wrong port, wrong identifier, or not a ZTE device |
| `framing-lost` | magic matched, length did not | the peer may not be `zte_icg_agg` |
| `device-refused` | the allowlist rejected a MAC | the `-devices` line to paste |
| `upstream-dial-failed` | the proxy could not reach the destination | check the server's own egress, and `-allow`/`-deny` |
| `bad-udp-datagram` | unparseable datagram | something else is sending to that port |

### Check it without a device

`icg-probe` speaks the real protocol — real handshake, real legs, real
per-packet striping — and exits non-zero on failure:

```sh
make icg-probe
./bin/icg-probe -server 1.2.3.4:10088 -udp 1.2.3.4:10000 -udp-legs 4 -legs 3 \
                -mac 02:00:5e:10:00:01 -fetch http://example.com/
```

It checks the handshake, that keepalives are answered, that every UDP leg
answers RTT sync **with the client's clock echoed unchanged** (get that wrong
and the device's scheduler writes the leg off), that an HTTP GET completes
through the proxy, that the same GET completes when its frames are transmitted
back-to-front across every leg, that cumulative ACKs arrive, and that framing
never desyncs.

The `-fetch` target must be reachable **from the concentrator**. The probe
resolves the name locally and ships the literal address, exactly as the device
does, so a geo-DNS or IPv6-only answer fails and looks like a server bug —
`neverssl.com` resolves IPv6-only from EC2, for instance. The probe prints the
address it shipped.

### Three device-side traps, learned the hard way

These come from running the device's own binary under `emu/` and watching it
fail. All three present as "the device never connects" and none of them produce
a useful message on the device.

1. **The device ships with logging off.** `ICGLogLevel=0` in `icg.conf` means
   *no output at all* — ZTE's own comment is `0-无，1-错误，2-警告，3-信息，4-调试`.
   A device that appears to be doing nothing may simply be refusing to say what
   it is doing. Set `ICGLogLevel=4` before you debug anything, and read
   `/logfs/zte_icg_agg_log`. Three of our debugging rounds were spent guessing at
   a stall this would have named outright.

2. **A WAN without carrier is silently ignored.** `is_wan_running` tests bit 6
   of the interface flags — `IFF_RUNNING` — so an interface that is `UP` but has
   no carrier never becomes a tunnel leg, and the device reports `change type:0`
   for every slot and opens nothing. If you expect four legs and get one, check
   carrier before you check anything else.

3. **The WAN address comes from a DHCP lease file, and a bad read zeroes it.**
   The device does not ask the kernel for a WAN's address and gateway; it reads
   them from `/tmp/ipv4config.<name>`, where `<name>` comes from a **fixed
   interface table**, not the interface's own name
   (`rmnet_data0`→`zte_mwan2`, `V3E1net0`→`zte_mwan3`, `V3E2net0`→`zte_mwan4`,
   `eth0`→`zte_wan`). The format is the one its own `dhcp.script` writes —
   shell `export` assignments with **double-quoted** values and a **trailing
   space** inside `GATEWAY`:

   ```sh
   export IFNAME="eth0"
   export PUBLIC_IP="10.77.0.2"
   export NETMASK="255.255.0.0"
   export GATEWAY="10.77.0.1 "
   ```

   A failed lookup does not fall back to the kernel — it *zeroes the address*
   and you get `CurIP[0.0.0.0]`, followed by `get invaid gateway!` (their
   spelling). See `emu/entrypoint.sh` for a working reproduction.

---

## Point a device at it

Re-read the warnings at the top first, and **verify every key against the live
config** before setting it — the names below are transcribed from the device's
strings dump and its `uci` state.

On the device:

```ini
# /home/icg/icg.conf
ForceUsingLocalInfo=1              # 1 = read [ServerInfo] locally, never ask MQTT
[ServerInfo]
AggregationServerIP=<your server>
AggregationServerTcpPort=10088
AggregationServerUdpStartPort=10000
AggregationServerTunIP=172.16.25.18
AggregationServerIcgId=<any non-zero>
```

```sh
uci set zwrt_router.network.opms_wan_mode=SMULTIWAN
uci set zwrt_router.icgmwan.IcgDevId=<non-empty>
uci set zwrt_router.icgmwan.AggServerIp=<your server>
uci set zwrt_router.icgmwan.IcgTcpAggPort=10088
uci set zwrt_router.icgmwan.IcgUdpAggPort=10000
uci set zwrt_router.icgmwan.AggregationServerTunIP=172.16.25.18
```

`TunnelIdentifier` is hex, so `-magic` takes hex too.

Read `zte_icg_agg_init`, `icg_agg_fw.sh`, `init_icg.sh` and `stop_icg.sh` in
full before running any of them: startup also removes hardware flow offload
(`rmmod shortcut_fe*`) and, on one path, remounts `/` read-write and moves
`/etc/init.d/firewall` aside.

### What success looks like

On the device, in `/logfs/zte_icg_agg_log`:

- `[HANDSHAKE][ICG STATE] send handshake rsp pkt and icg state ICG_AND_SRV_BOTH_OK`
- `zwrt_router.tmp_router.icg_agg_status` = `1`
- **no** `[AGG][zombie]` lines — those mean the device gave up on us

In the concentrator's UI: the device present, `ICG_AND_SRV_BOTH_OK`, one leg per
WAN with a measured RTT, and `reorder_skipped` / `late` staying at zero.
