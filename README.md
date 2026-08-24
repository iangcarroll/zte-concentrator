# zte-coord

A self-hosted concentrator for **ZTE's proprietary multi-WAN packet bonding**,
plus the reverse-engineered protocol it speaks.

Some ZTE 5G CPEs (the MU5252, for one) ship a bonding client, `zte_icg_agg`,
that stripes a single TCP connection across every WAN the device has — 5G plus
two LTE modems — to a cloud "ICG" concentrator. It is genuine per-packet
bonding: two global sequence spaces, reordering, selective retransmission,
jitter smoothing, per-leg RTT scheduling. It is not MPTCP and not mwan3, and one
connection really does get faster.

The catch is that the concentrator is ZTE's, in mainland China, metered, and the
tunnel has no encryption of its own — so all your LAN traffic transits it in the
clear. This repo is the other end of that tunnel, so the device can bond through
infrastructure you control instead.

The protocol was recovered from the device's own binary and a live capture. It
is documented in [`docs/PROTOCOL.md`](docs/PROTOCOL.md), which tags every claim
**PROVEN** or **INFERRED**.

## Quick start

```sh
make                                   # bin/icgd and bin/icg-probe
./bin/icgd -tcp :10088 -udp-base 10000 -udp-legs 4 -devices <device-mac> -v

# In another terminal: prove it works, without needing a device.
./bin/icg-probe -server 127.0.0.1:10088 -udp 127.0.0.1:10000 -udp-legs 4 \
                -legs 3 -mac <device-mac> -fetch http://example.com/
```

```
  PASS connect          3 tcp leg(s), 4 udp leg(s)
  PASS handshake        ICG_SERVER_HANDSHAKE_ACK in 1.07s, then ICG_CONFIRM_SERVER_ACK sent
  PASS keepalive        TUNNEL_DETECT received (3 seen so far)
  PASS rtt-sync         4/4 udp legs answered with our clock intact
  PASS data-path        GET http://example.com/ -> "HTTP/1.1 200 OK"
  PASS striping         13 chunks reversed across 3 legs, reassembled intact -> "HTTP/1.1 200 OK"
  PASS cumulative-ack   5 received, so the device could free its send stash
  PASS framing          no stream resyncs
```

Deploy it to a server, and point a device at it:

```sh
make deploy HOST=ubuntu@1.2.3.4 ARGS="--devices 02:00:5e:10:00:01"
```

Then read [`docs/OPERATING.md`](docs/OPERATING.md) — **before** you touch the
device, because getting it wrong cuts the device's LAN off by design.

## Read this before deploying

**The protocol has no authentication and no encryption.** The only thing
resembling a credential is a 4-byte constant published in the device's own
config file. Anyone who can reach the tunnel ports can open a session and use
your box as an open proxy. `-devices` (a MAC allowlist) and `-allow` (an egress
allowlist) exist for this, and the deploy script will not open a firewall port
unless you ask it to. Details in [`docs/OPERATING.md`](docs/OPERATING.md).

**It has not been tested against the real device yet.** It has been deployed to
three Linux distributions and validated over the public internet against a
client that speaks the real protocol — but that client and this server were
written from the same notes, so a misreading of the protocol would be reproduced
on both sides and pass anyway. [`docs/STATUS.md`](docs/STATUS.md) says exactly
what is proven, what is guessed, and what would most likely break first.

## Layout

```
icg/                  protocol codec: framing with stream resync, the complete
                      type/opcode table, body marshalling. No I/O.
  testdata/           42 redacted frames from a live capture, as round-trip
                      fixtures
icg/concentrator/     the server: TCP + N UDP tunnel listeners, sessions keyed
                      by tun IP, both global sequence spaces reassembled across
                      legs, retransmission, cumulative ACKs, a transparent TCP
                      proxy off the recovered 5-tuple, UDP NAT, and an
                      observability API + web UI
icg/client/           the client side — the half zte_icg_agg speaks. Enough to
                      validate a concentrator, not a device reimplementation
cmd/icgd/             the concentrator daemon
cmd/icg-probe/        validates a concentrator by pretending to be a CPE
deploy/               icgd-deploy.sh (runs on your laptop) and icgd-install.sh
                      (runs on the server; POSIX sh, readable before it runs)
docs/                 PROTOCOL.md, OPERATING.md, STATUS.md
```

## Diagnosing a device

Worth knowing, because it drove a lot of the design: `zte_icg_agg` was written
to talk to ZTE's own cloud and tells its operator essentially nothing when
pointed elsewhere. A wrong identifier, a refused device and an unreachable
upstream all present the same way — as nothing happening.

So `icgd` explains instead. Every failure you can act on becomes a notice
carrying the fix, in the log and in the web UI, without needing `-v`:

```
wrong TunnelIdentifier: the peer sent magic 0xdeadbeef, we expect 0x12345678
  peer: 203.0.113.9:41221
  fix:  set icg.conf TunnelIdentifier=12345678 on the device, or restart icgd with -magic deadbeef
```

## Related

The device-side reverse engineering — how the feature is gated (one GPIO pin),
the firmware blobs, the disassembly tooling, the MQTT control plane, and the
rest of the CPE fleet management — lives in the private `iangcarroll/zte` repo.
