# Running the real ZTE binary locally

A container that runs the device's actual bonding client, `zte_icg_agg`,
against a concentrator on your laptop — so the server can be tested against
the real thing instead of against a client written from the same notes.

That last part is the whole point. [`../docs/STATUS.md`](../docs/STATUS.md) calls
it out as the single largest risk in this project: `icg-probe` and the server
were written from the same reading of the protocol, so any misreading is
reproduced on both sides and the tests pass anyway. Only the device's own binary
can settle it.

## Why this is possible at all

Three things line up:

1. **The binary needs almost nothing.** It is linked against fifteen shared
   libraries, most of them ZTE proprietary — but it *imports* only six non-libc
   symbols: `dzlog`, `dzlog_init`, `zlog_fini`, `zte_key_syslog_append`,
   `libzte_router_uci_get` and `libzte_router_uci_set`. Five are logging and one
   pair is a uci get/set. `shim.c` provides all six in about 150 lines, and every
   other `DT_NEEDED` entry is satisfied with a symlink to it: the musl loader
   resolves by filename and does not care that `libsqlite3.so.0` happens to
   contain a logging shim it never calls. No ubus, no uci, no mbedTLS, no
   OpenWrt userland.

2. **The device is musl aarch64,** so Alpine's `/lib/ld-musl-aarch64.so.1` is
   the loader the binary already asks for.

3. **On an arm64 host it runs natively.** No QEMU, no emulation, no slowdown.
   (On x86-64 it still works via `binfmt_misc`/QEMU, just slower — see below.)

Verify the import claim yourself:

```sh
r2 -q -c ii /path/to/zte_icg_agg | grep -vE 'libc|GLIBC'
```

## Use it

The proprietary binary is deliberately **not** in this repo. Get it from the
device (`adb pull /usr/bin/zte_icg_agg`) or from the private `zte` repo's
`research/firmware/icg/`, and drop it in `blobs/`:

```sh
cp /path/to/zte_icg_agg blobs/
make pull            # CI already built it; this is much faster than `make build`

# In one terminal: the concentrator. --http on all interfaces so the container
# can be pointed at the host.
cd .. && make icgd && ./bin/icgd -tcp :10088 -udp-base 10000 -udp-legs 4 -v

# In another: the real client.
make run
```

`make run` mounts the binary, creates dummy `rmnet_data0` / `V3E1net0` WAN
interfaces and a `br-lan` bridge, fills the server address into the device's own
`icg.conf`, and execs the binary. What you are looking for on its stderr is the
device's own state machine reporting success in its own words:

```
[NOTICE] src/handle/icg_handshake.c:… icg_handshake_proc() [HANDSHAKE][ICG STATE][INIT] start send handshake with config
[NOTICE] src/handle/icg_state.c:…    update_icg_proxy_state() [ICG STATE] oper: ICG_SERVER_HANDSHAKE_ACK(3) update ICG_SERVER_READY
[NOTICE] src/handle/icg_handshake.c:… icg_handshake_proc() [HANDSHAKE][ICG STATE] send handshake rsp pkt and icg state ICG_AND_SRV_BOTH_OK
[shim] uci_set(zwrt_router.tmp_router.icg_agg_status = 1)
```

That last line is the device declaring the tunnel up. And the thing to watch for
is its absence, or `[AGG][zombie] … agg_server_exit`, which is the client giving
up on the concentrator.

| variable | default | what it does |
|---|---|---|
| `SERVER_IP` | `172.17.0.1` | the concentrator as seen from the container. `host.docker.internal` on Docker Desktop |
| `TCP_PORT` / `UDP_BASE` | `10088` / `10000` | must match the concentrator |
| `WANS` | `rmnet_data0 V3E1net0` | dummy WAN links to create; names must appear in `icg.conf`'s `AggNetcard` |
| `TRACE` | `0` | `1` runs it under `strace -e trace=network,openat` |

Config lives in `etc/uci.conf` (the shim's uci backing store) and
`home-icg/icg.conf` (the device's own file, templated). Both are worth reading:
between them they are the entire local gate on this feature.

## State of this harness

**Verified:** the import analysis, which is the load-bearing claim — six
non-libc symbols, nothing from any of the four crypto libraries, `libc.so`
resolving to Alpine's musl loader. Checked directly against the binary, and
confirmed by running Alpine aarch64 and asking the loader what it wants:

```
$ docker run --rm --platform linux/arm64 -v ./zte_icg_agg:/x/a:ro alpine:3.20       /lib/ld-musl-aarch64.so.1 --list /x/a
        libc.so => /lib/ld-musl-aarch64.so.1
  Error loading shared library libzlog.so.1.2: No such file or directory
  ... (thirteen more missing FILES)
  Error relocating /x/a: zlog_fini: symbol not found
  Error relocating /x/a: libzte_router_uci_get: symbol not found
  Error relocating /x/a: dzlog: symbol not found
  Error relocating /x/a: libzte_router_uci_set: symbol not found
```

Fourteen missing files, but only four unresolved *symbols* — the rest resolve
once the shim is in place.

**Built in CI:** `.github/workflows/emu.yml` builds the image on every change,
asserts that the shim still exports every symbol the binary imports and that
every `DT_NEEDED` name has a file, checks the entrypoint reaches its exec, and
publishes to `ghcr.io/iangcarroll/zte-coord/emu:main`. `make pull` fetches that
instead of building locally — which matters, because building means installing a
compiler into an aarch64 image and that is slow or impossible on a poor link.

The two contract files (`etc/expected-imports.txt`, `etc/expected-libs.txt`) are
what CI asserts against, and `./refresh-contract.sh /path/to/zte_icg_agg`
regenerates them from the binary so they cannot drift from it silently.

**Not yet verified:** the harness has never been *run* against the real binary
end to end — CI cannot, because the blob is not in the repo, and the connection
this was written on could not build the image locally. Treat the runtime
behaviour as designed-but-unexercised until someone does
`make pull && make run` and sees `ICG_AND_SRV_BOTH_OK`.

## What this does and does not prove

**Does:** that the real client accepts our handshake, agrees on the framing,
reaches `ICG_AND_SRV_BOTH_OK`, keeps the session alive, and pushes real traffic
through the transparent proxy. That is exactly the gap `docs/STATUS.md` names.

**Does not:**

- **Throughput or scheduling.** All the dummy WANs egress through one container
  interface, so there is one physical path with one RTT. Striping happens, but
  no leg is genuinely faster than another, so the min-RTT scheduler has nothing
  to choose between.
- **The DIAG/modem side.** No radios, no `ubus`, no `zte_router` orchestrator.
- **Anything the missing libraries do.** They are stubs. If the binary ever
  starts calling into `libzteencrypt` for the data plane it would fail here —
  which would itself be a finding, since the data plane is supposed to have no
  cryptography at all.
- **The GPIO gate.** Bypassed by writing `SMULTIWAN` straight into the shim's
  uci store, which is what the hardware key would otherwise do.

## Non-arm64 hosts

The container is `linux/arm64`. On an x86-64 host, register the QEMU handlers
once and the same commands work, slower:

```sh
docker run --privileged --rm tonistiigi/binfmt --install arm64
```

## Safety

`icg.conf` here is the device's own file with **every ZTE endpoint removed** —
the MQTT brokers, the cached concentrator, and `UdpEchoServerIp`, which
otherwise points at `119.23.22.156`. Nothing in this container talks to ZTE.

`/sbin/icg_agg_fw.sh` is stubbed to a no-op. The real one installs the
netfilter and policy-routing plumbing, including the blanket LAN `DROP` that
makes a misconfigured device unreachable. Inside a container that would be
harmless, but it is also not what we are testing.
