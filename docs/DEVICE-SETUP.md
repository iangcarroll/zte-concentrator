# Pointing a device at your own concentrator

A complete manual walkthrough for a ZTE MU5252 ("TOPFLOW"). No extra tooling is
required — everything here is `uci`, a text edit and a `mount`, run over a root
shell on the device.

Read [`OPERATING.md`](OPERATING.md) first for how to run `icgd`, and
[`STATUS.md`](STATUS.md) for how much to trust any of this.

---

## ⚠ Read this before you touch anything

**`SMULTIWAN` with an unreachable concentrator turns the LAN into a walled
garden, by design.** `icg_agg_fw.sh` installs a blanket
`iptables -A client_access_network -j DROP` when `AggregationServerTunIP` is
empty. On a device that is somebody's only gateway, that is an outage.

Two things make this recoverable, and you want both in place before you start:

1. **An out-of-band shell.** ADB is over USB, so it survives the LAN going away.
   Do not do this over Wi-Fi with no other way in.
2. **A tested revert.** Know that this works before you need it:
   ```sh
   uci set zwrt_router.network.opms_wan_mode=MULTIWAN
   uci commit zwrt_router
   /etc/init.d/network reload
   ```

Also worth knowing: bringing the tunnel up **resets existing connections** on
the LAN, because every TCP flow is re-established through a transparent proxy.

---

## 0. What you need

| | |
|---|---|
| a root shell on the device | out-of-band, ideally ADB over USB |
| `icgd` running and reachable | see [`OPERATING.md`](OPERATING.md) |
| the device's **eth0** MAC | for the concentrator's allowlist — see §3 |

## 1. Find the settings the client actually uses

The client reads `/home/icg/icg.conf`. The keys that matter:

```sh
grep -E '^(TunnelIdentifier|ForceUsingLocalInfo|AggregationServer)' /home/icg/icg.conf
```

```ini
TunnelIdentifier=12345678          # must equal icgd -magic. Parsed as HEX.
ForceUsingLocalInfo=2              # 0=cloud 1=local file 2=ask the MQTT broker
AggregationServerIP=47.101.137.128 # the vendor's concentrator
AggregationServerTcpPort=10088     # must equal icgd -tcp
AggregationServerUdpStartPort=10000# must equal icgd -udp-base
AggregationServerTunIP=172.30.0.88 # the tunnel address the client takes
AggregationServerIcgId=88          # session id, and the source for IcgDevId
```

Two traps here:

- **`TunnelIdentifier` is hexadecimal despite looking decimal.** `12345678` is
  `0x12345678`, and appears on the wire little-endian as `78 56 34 12`. Start
  `icgd` with `-magic 12345678` and the two agree.
- **The ports are the *local* ones.** In cloud mode the broker hands out
  different ports per session (10039, 10280-10281 in one observed case), so what
  you see in a packet capture is not what a local-mode client will connect to.
  Your concentrator must listen on the values in *this file*.

## 2. Set `ForceUsingLocalInfo=1` and your address

`ForceUsingLocalInfo=1` makes the client read `[ServerInfo]` straight out of the
local file and **never contact the vendor's MQTT broker** — no dispatch, no
entitlement check, no quota.

**`/home/icg` is on the read-only rootfs, so you cannot simply edit the file.**
`mount -o remount,rw /` does not help either: it returns `EIO`, because "flash
protect" holds the block device read-only *below* the filesystem. Worse, it
leaves `/` reporting `rw` while every write still returns `EROFS`.

Publish a patched copy with a bind mount instead — root can mount over a
read-only file:

```sh
mkdir -p /data/icg
cp /home/icg/icg.conf /data/icg/icg.conf

sed -i 's#^ForceUsingLocalInfo=.*#ForceUsingLocalInfo=1#'          /data/icg/icg.conf
sed -i 's#^AggregationServerIP=.*#AggregationServerIP=YOUR.IP.HERE#' /data/icg/icg.conf

mount -o bind /data/icg/icg.conf /home/icg/icg.conf

# confirm the device now sees your values
grep -E '^(ForceUsingLocalInfo|AggregationServerIP)=' /home/icg/icg.conf
```

Make it survive a reboot by re-mounting from `/etc/rc.local` (that path *is*
writable), inserting before the trailing `exit 0`:

```sh
[ -f /data/icg/icg.conf ] && mount -o bind /data/icg/icg.conf /home/icg/icg.conf
```

> `/etc/rc.local` is **not** preserved across a firmware update. After a FOTA the
> mount is gone and the device falls back to the vendor's config — the safe
> direction to fail, but re-apply this afterwards.

## 3. Allowlist the right MAC

`icgd -devices` matches the MAC in the handshake. **The client presents the
`eth0` MAC**, which is *not* the WLAN MAC, and `eth0` need not even have a cable
in it:

```sh
cat /sys/class/net/eth0/address
```

Get this wrong and the concentrator logs

```
level=WARN msg="device 00:55:7b:b5:7d:f8 is not in the allowlist"
```

with nothing pointing at the real cause. Add that address to `-devices` and
restart `icgd`.

## 4. Provide `IcgDevId`

The vendor's init script refuses to start the data plane without it:

```sh
opms_wan_mode=`uci -q get zwrt_router.network.opms_wan_mode`
[ "$opms_wan_mode" != "SMULTIWAN" ] && return
icg_id=`uci -q get zwrt_router.icgmwan.IcgDevId`
[ -z "$icg_id" ] && return
```

In cloud mode the broker populates it. In local mode nothing does, so set it
yourself, matching `AggregationServerIcgId`:

```sh
uci set zwrt_router.icgmwan.IcgDevId=88
uci commit zwrt_router
```

> **This does not stick.** The value is cleared whenever the mode leaves
> `SMULTIWAN`, so after toggling the switch off and on again you must set it
> again before the data plane will start. Check it every time:
> `uci -q get zwrt_router.icgmwan.IcgDevId`

## 5. Enable aggregation

Activation is a **physical switch** on the device, read as a GPIO key. Leave it
authoritative rather than forcing the uci value in software — the switch is what
the vendor's own code watches.

The mapping is not what you would guess:

```
$ cat /sys/devices/platform/soc/soc:gpio_keys/key_state
0408:0,0010:1,      <- switch OFF -> opms_wan_mode=MULTIWAN
0408:0,0010:0,      <- switch ON  -> opms_wan_mode=SMULTIWAN
```

**Key `0x010` is the aggregation switch and `0` means enabled.** `0x408` reads
`0` in both states and is not the gate.

Flip it, then confirm:

```sh
uci -q get zwrt_router.network.opms_wan_mode   # SMULTIWAN
pgrep -l zte_icg_agg                            # running
ip -br addr show tun0                           # 172.30.0.88/24
```

## 6. Verify

On the concentrator you want legs binding to a session:

```
msg="tunnel leg connected"  leg=tcp:198.51.100.7:31853
msg="leg bound to session"  leg=tcp:198.51.100.7:31853 icg_id=0.0.0.88
msg=session icg_id=0.0.0.88 idle=29ms dropped=0
```

Several legs from **different source addresses** is the point — that is each WAN
striping into one session.

On the device, traffic should be moving through the tunnel:

```sh
ip -s link show tun0        # RX/TX climbing, errors 0, dropped 0
iptables -t nat -S | grep 14000   # the transparent proxy DNAT
```

`idle=` in the session line is time since the last packet, not a verdict — check
the `tun0` counters for whether anything has actually flowed.

## 7. Undo

```sh
# 1. put the physical switch back (or, if you must, in software)
uci set zwrt_router.network.opms_wan_mode=MULTIWAN
uci commit zwrt_router

# 2. drop the config overlay so the vendor file shows through again
umount /home/icg/icg.conf
rm -f /data/icg/icg.conf
#    ...and remove the mount line from /etc/rc.local

# 3. restore networking
/etc/init.d/network reload
```

---

## Troubleshooting

| symptom | cause |
|---|---|
| `wrong TunnelIdentifier: the peer sent magic 0x20544547` | that is `"GET "` — something is speaking HTTP at the tunnel port. Usually a browser or `wget` aimed at it, not the client |
| `device ... is not in the allowlist` | allowlisted the WLAN MAC; it wants **eth0**'s (§3) |
| switch on, but no process and no `tun0` | `IcgDevId` is empty — it was cleared by the last mode change (§4) |
| LAN has no internet, only 192.168.56.1/57.1 reachable | the fail-closed DROP: the client has no usable concentrator. Revert to `MULTIWAN` |
| `read-only file system` editing `icg.conf` | expected — use the bind mount (§2), not a remount |
| everything connects, no traffic | normal if nothing is behind the device. Only LAN clients are proxied; the device's own traffic is not |
