# Status: what is trustworthy, and what is not

An honest account of what this implementation has and has not been shown to do.
[`PROTOCOL.md`](PROTOCOL.md) is the specification; [`OPERATING.md`](OPERATING.md)
is how to run it.

Last updated 2026-08-24.

## Where things stand

| part | state |
|---|---|
| Wire framing | **done**, proven both directions ([§2](PROTOCOL.md)) |
| Packet type table | **done**, proven (§3) |
| Handshake opcodes + state machine | **done**, proven (§4, [§6](PROTOCOL.md)) |
| ACK / retransmit / telemetry opcodes | **done**, proven incl. both range bodies (§5) |
| TCP data body + tcp_optcodes | **done**; 0/1/3 proven, 4/5 inferred (§7) |
| UDP + ICMP data body | **done**, proven — payload is a raw IPv4 packet (§8) |
| Sequence resynchronisation | numbering proven, one body unread (§9) |
| Protocol codec | **done**, `icg/`, fixtures from a live capture |
| Concentrator | **done for TCP and UDP**, `icg/concentrator` + `cmd/icgd`. ICMP relaying not implemented |
| Client, for validation | **done**, `icg/client` + `cmd/icg-probe` |
| Device admission control | **done**, `-devices` MAC allowlist (not authentication) |
| Observability API + web UI | **done**, `-http` with shared-secret auth |
| Deployment | **done**, `deploy/`, clean install and update on three distros |
| Tested against a real server | **done**, over the public internet |
| Running the real device binary locally | **harness built**, [`../emu/`](../emu/) — see below |
| **Tested against the real device** | **in progress** — the harness closes this, once run |

## Testing against the real binary

The gap below — that `icg-probe` and the server were written from the same notes
— can be closed without a device, and [`../emu/`](../emu/) is the harness for
it: a container that runs the device's actual `zte_icg_agg` against a
concentrator on your laptop.

It is feasible because of a genuinely lucky property of the binary. It is linked
against fifteen shared libraries, most of them ZTE proprietary, but it
**imports only six non-libc symbols**:

```
dzlog  dzlog_init  zlog_fini  zte_key_syslog_append
libzte_router_uci_get  libzte_router_uci_set
```

Five are logging and one pair is a uci get/set. Nothing from `libubus`,
`libuci`, `libsqlite3`, `libcares`, `libmbedcrypto`, `libzteencrypt`,
`libztecrypto` or `libztecryptofilewrapper` is called directly — those are
`libzterouter`'s transitive dependencies, and `libzterouter` is one of the two
things we replace. So ~150 lines of C stand in for the entire ZTE userland, and
every other `DT_NEEDED` entry is satisfied with a symlink to that same shim.

Two more things line up: the device is **musl aarch64**, so Alpine's
`/lib/ld-musl-aarch64.so.1` is the loader the binary already asks for; and on an
arm64 host the container runs **natively**, no emulation.

Worth noting what that import list also tells us: the data plane genuinely has
no cryptography. It is not that we found no crypto calls — there is no crypto
library it could call into, because it imports nothing from any of the four
crypto libraries it links against.

What the harness settles: whether the real client accepts our handshake, agrees
on the framing, reaches `ICG_AND_SRV_BOTH_OK`, stays alive, and pushes traffic
through the proxy. What it cannot settle: throughput and scheduling (all the
dummy WANs share one physical path, so no leg is really faster than another),
and anything the stubbed libraries would have done.

## What is deliberately not implemented

- **Tunnelled ICMP relaying (type 1).** The format is proven and the frames are
  parsed and counted, but relaying them needs a raw socket or a tun device;
  everything else uses ordinary sockets and needs no privileges. Pings from the
  LAN will not work. Nothing else is affected.
- **FEC.** Configured in `icg.conf` but disabled, and no FEC frame type was
  identified in the binary.
- **The four telemetry report bodies** (type 4, opcodes 11–14). Logged and
  discarded; layouts unmapped.
- **Sending `tcp_optcode` 4/5 (block/unblock).** Inbound ones are logged. We do
  not generate downlink fast enough for flow control to matter, and the
  numbering is inferred rather than proven.

## Design decisions worth knowing

- **One goroutine per session owns all mutable state.** Both sequence
  counters, both reassemblers, the leg table and the flow table are touched only
  by `Session.run`. Legs post frames in over a channel; upstream sockets post
  data back over another. That is what makes sequence assignment correct without
  a lock per field. `go test -race` passes at `-count=5`.
- **The reassembler holds the first packets for a 25 ms settle window** before
  choosing a starting sequence number. ZTE's client latches onto the first
  packet it *sees*, but with per-packet striping the first to arrive is not the
  first sent — so latching immediately silently discards everything below it.
  This is a deliberate improvement over the device's behaviour, and it was a
  real bug found by a test, not a hypothetical.
- **Retransmissions are served on the leg that asked**, not the scheduler's
  choice: that leg is demonstrably alive and it is the one with the gap.
- **Downlink leg selection is lowest-RTT-first**, matching the device's own
  `TcpTunnelSelectModel=2`. The RTT comes free from the RTT-sync exchange: the
  client echoes our `ICG_UDP_CHNN_RTT_SYNC_ACK` back verbatim as
  `ICG_UDP_CHNN_RTT_ACK`, so the server timestamp inside it is ours to subtract.

## What was actually tested, and on what

**Deployed and validated on real servers, 2026-08-24.** Three EC2 `t4g.small`
(arm64) instances in `us-west-2`, deployed with `deploy/icgd-deploy.sh` from a
laptop, then driven with `cmd/icg-probe` **over the public internet** — real
ICG protocol, real WAN legs, real latency. All resources have been torn down.

| distro | deploy path exercised | `icg-probe` |
|---|---|---|
| Ubuntu 24.04.4 LTS | clean install, then update with a config change | 8/8 pass |
| Amazon Linux 2023 | clean install | 8/8 pass |
| Debian 12 (bookworm) | update over an existing install | 8/8 pass |

The link during testing was in-flight wifi at **~615–700 ms RTT** with periodic
total dropouts, which turned out to be a better test than a good link would
have been. On the live server, after a run that transmitted a striped request
back-to-front across three legs:

```
session 172.16.25.18 state=ICG_AND_SRV_BOTH_OK admitted=True mac=02:00:5e:10:00:01
   legs=4  frames=35 in/837 out  tcp_flows=2  reorder_skipped=0  late=0  dial_fails=0
     udp 205.220.129.27:44929  rtt=616ms
     udp 205.220.129.27:51489  rtt=617ms
     udp 205.220.129.27:52543  rtt=615ms
     udp 205.220.129.27:63303  rtt=653ms
```

`reorder_skipped=0, late=0` is the number that matters: nothing was dropped or
stepped over despite deliberate reordering at 600 ms. The per-leg RTTs are the
concentrator measuring them itself, from the client's `ICG_UDP_CHNN_RTT_ACK`
echo — so the scheduler had real numbers to work with.

Also verified live: the device allowlist (an unknown MAC gets no
`ICG_SERVER_HANDSHAKE_ACK` and the session never leaves `ICG_INIT_STATE`), the
observability API through an ssh tunnel, and `401` for an unauthenticated
request to it.

### What real-network testing found that loopback did not

Worth recording, because it is the argument for having done this at all:

1. **The probe's downlink collector assumed frames arrive in order.** It
   anchored reassembly on the first frame *received* rather than the lowest
   sequence number *seen*, so at 700 ms it silently discarded everything below
   that anchor and reported "0 bytes". On loopback, frames never reorder and it
   passed every time. Fixed, and the failure message now names the sequence
   numbers it is holding.
2. **My own striping test was not testing striping.** It allocated sequence
   numbers at transmit time, so sending the chunks in reverse produced a
   reversed *byte stream*, not reordered delivery — and the upstream's
   `HTTP 400` was the concentrator being faithfully correct. Sequence
   allocation is now separate from transmission (`Flow.WriteAt`), and the check
   requires an HTTP 200 rather than merely a status line.
3. **A listener race in the observability server** — `Serve` wrote `ln` while
   `Addr` read it. Caught by `-race`, same shape as one already fixed on the
   concentrator's own listeners. Both now use a `Ready()` channel.
4. **The deploy probe read `/etc/icgd` unprivileged.** The directory is `0750
   root:root`, so `test -f .../icgd.env` was always false, so every update
   decided the config was missing and rewrote it — silently defeating the one
   behaviour the update path exists to provide. It now escalates for that read
   and says so if it cannot.
5. **The installer never created the directories it installs into.** Invisible
   on a real server (`/usr/local/bin` always exists) but a real latent bug,
   found by running it against a scratch tree.

And one that was not a bug at all but looked exactly like one:
`neverssl.com` resolves **IPv6-only** from EC2, and the IPv4 a roaming client
resolves is not reachable from `us-west-2`. The probe ships a literal address
exactly as the device does, so the `-fetch` target must be reachable *from the
concentrator*. The probe now prints the address it shipped and says this in the
failure text.

## Honest assessment

**What is solid.** The framing, type/opcode map, handshake and body layouts are
read out of the disassembly *and* cross-checked against 42 real frames that
round-trip byte-for-byte. The concentrator has now completed handshakes,
proxied HTTP, reassembled deliberately reordered striped traffic, measured
per-leg RTT and served cumulative ACKs on three Linux distributions over the
open internet at 600 ms RTT, with nothing dropped.

**What is still untested where it counts.** None of it has faced the real
`zte_icg_agg`. `icg-probe` is a client *I* wrote from the same notes as the
server, so any misreading of the protocol is reproduced identically on both
sides and the probe will happily pass. That remains the single largest risk and
no amount of further self-testing reduces it.

**What would most likely break first, in order:**

1. **Liveness.** `device_zombie_state_check` releases resources after 30 s of
   silence and stops the daemon after 150 s (§6). What refreshes its activity
   timestamp is inferred, not proven — if it is not "any received frame", our
   1 Hz tunnel-detect may not count and the session will drop every 30 s.
2. **The handshake being accepted.** `refresh_icg_resource` only checks the
   opcode, so this *should* work, but it is the first thing to watch.
3. **Sequence-space start.** Whether the client's counters restart at 0 after a
   handshake is unverified; the capture began mid-session. Our reassembler
   latches onto whatever it sees, so this should not matter — but whether the
   client accepts a downlink space starting at 0 is untested.
4. **The downlink CRC32.** We send 0 because ZTE's server does. If the client
   validates it under some configuration (`TcpDownCrcSwitch`), downlink TCP
   breaks entirely.
5. **Sequence resync under real loss.** We answer requests with our current
   position; whether that is what the client expects is unverified ([§12](PROTOCOL.md)).

**Effort to close the gap: small, and it is all bench work.** One session
against the real device with `-v` on the concentrator and
`/logfs/zte_icg_agg_log` on the client would confirm or refute all five in an
afternoon, because the client logs its own state transitions by name and those
names are the ones this code uses. The web UI exists precisely so that session
does not require reading a journal. The prerequisite is not more RE — it is a
device we are allowed to point at ourselves.

## Next actions

1. **Bench test against the real device** (needs operator sign-off; see the
   warnings in [`OPERATING.md`](OPERATING.md)).
   Watch for: `ICG_AND_SRV_BOTH_OK` in the device log, no `[AGG][zombie]` lines,
   `icg_agg_status=1`, and `Resyncs = 0` on our side.
2. Close the non-blocking protocol gaps in
   [§12 of the protocol doc](PROTOCOL.md), in particular the
   activity-timestamp writers (point 1 above).
3. Implement ICMP relaying if pings turn out to matter.
4. Add a metrics endpoint; `Session.Stats` and `Reorder`'s counters exist but
   are only logged today.
5. ~~Test the deploy scripts on a real server.~~ **Done** — see above. Still
   untested on a real server: `--uninstall`, `--open-firewall`, and rollback
   after a genuinely bad binary (all three were exercised against a scratch
   tree via `ICGD_ROOT`).

