# The ZTE ICG bonding protocol

The wire specification for ZTE's proprietary "ICG" (Intelligent Convergence
Gateway) multi-WAN packet bonding — the protocol a ZTE CPE speaks to its
aggregation concentrator. Reverse-engineered from the device's own binary and a
live capture; this repo implements it.

Read [`STATUS.md`](STATUS.md) for what is trustworthy and what is not, and
[`OPERATING.md`](OPERATING.md) to run a concentrator.

Addresses cited below are offsets into the device's own `/usr/bin/zte_icg_agg`.
Pull your own copy off a device to follow along; the binary is ZTE's and is not
redistributed here.

Target: `/usr/bin/zte_icg_agg` `2.2.2.0(932e8c3) Aug 8 2026`, MU5252
`EN_CN_MU5252V1.0.0B20`.

Every claim below is tagged:

- **PROVEN** — read directly out of the disassembly, or observed in
  `research/firmware/icg/pcap/icg_outer.pcap`, usually both.
- **INFERRED** — a reasoned guess. Called out individually. Do not build on
  these without checking.

All addresses are file offsets in `zte_icg_agg` (a PIE with base 0, so they are
also vaddrs in the text segment).

---

## 1. How this was recovered

`zte_icg_agg` is stripped: no section headers, no symbol table, 130 dynamic
symbols and one exported function (`crc32`). radare2's own analysis finds ~94
functions out of ~738. Three things make it tractable, and they are all
implemented in the `zte` repo's `research/tools/icg/`:

1. **`.eh_frame_hdr` survives.** The `PT_GNU_EH_FRAME` segment at file `0x3fdd8`
   still carries the FDE binary-search table, which is a list of every function
   entry address — 738 of them. `icgre.func_starts()` parses it.
2. **ZTE's log macro leaks names.** `dzlog(file, filelen, func, funclen, line,
   level, fmt, ...)` is called with `__FILE__` and `__func__` as string
   literals, so almost every function contains an `ADRP`/`ADD` pair pointing at
   a string that *is its own name*. `icgre.Img._scan()` forward-simulates
   `ADRP`/`ADR`/`ADD`/`SUB`/`LDR` to collect those references and names 317
   functions. Combined with the ~1400-line strings dump (which preserves source
   paths like `src/tcp/tcp_sort.c`) this is effectively a source map.
3. **Relocations are in place.** Indirect calls all look like
   `adrp xN, PAGE / ldr xN, [xN, OFF] / blr xN`, and the target is simply the
   qword stored at `PAGE+OFF` in the file (`R_AARCH64_RELATIVE` with the addend
   written into the slot). `icgre.Img.resolve_call()` reads it and maps it to
   either an import name (from r2's `ir` table) or a recovered function name.

The Go implementation of everything below is [`../icg`](../icg), with 42
redacted frames from the capture committed as round-trip fixtures in
[`../icg/testdata/frames.txt`](../icg/testdata/frames.txt).

The tooling that recovered it (`icgre.py`, `dis.py`, `icgpcap.py`,
`mkfixtures.py`) lives in the `zte` repo under `research/tools/icg/`, alongside
the firmware blobs it operates on. `dis.py` needs `r2` on `$PATH`; the rest are
pure Python.

Two enum name tables are stored verbatim in the binary as arrays of `const
char*` at file offset `0x50048` and `0x500a0` (vaddr `0x60048` / `0x600a0`).
Because the array index *is* the enum value, these give the numbering for free.

---

## 2. Framing — **PROVEN**

Identical on the TCP leg and every UDP leg, and identical in both directions.

```
offset  size  field          notes
------  ----  -------------  ----------------------------------------------
0x00      4   magic          u32 LE. icg.conf TunnelIdentifier, read as HEX
                             (=12345678 -> bytes 78 56 34 12)
0x04      4   body_length    u32 LE. Excludes these 8 bytes. Includes the
                             10-byte sub-header below.
--- body (body_length bytes) ---
0x08      4   icg_id         opaque u32; AggregationServerIcgId (see note)
0x0c      1   type           packet class, see §3
0x0d      1   opcode         sub-type within the class
0x0e      4   seq            u32 BIG-endian (htonl/ntohl). Meaning depends
                             on type: sequence number, or CRC32, or 0.
0x12    ...   payload        body_length - 10 bytes
```

Total frame = `8 + body_length`. Frames are length-delimited and **may be
concatenated** inside one TCP segment; `recv_tcp_stream` (`0x2442c`) /
`find_tcp_tunnel_header_again` resynchronise on the magic if framing is lost.

In-memory this maps to a packet object where the *send* buffer starts at
`pkt+0x108` (magic at `+0x108`, payload at `+0x11a`), while on *receive* only
the body is stored at `pkt+0x108` (payload at `+0x112`) and
`pkt->data_len (+0x18) = body_length - 10`. That asymmetry is why the same
struct offsets mean different things in the send and receive paths — worth
remembering when reading the disassembly.

### The field at `0x08` is the ICG **id**, not an IP — **PROVEN**

It holds `icg.conf`'s `AggregationServerIcgId`: the opaque identifier ZTE's MQTT
dispatch assigns to a CPE. We use it as the session key.

**Proven by experiment**, not by reading the capture: setting
`AggregationServerIcgId=305419896` (`0x12345678`) on the real binary made every
frame carry `0x12345678` in this field, with `AggregationServerTunIP` left
unchanged.

> **This documentation previously said the field carried
> `AggregationServerTunIP`, the concentrator's tun address. That was wrong.**
> It is worth recording why, because the wrong reading was *entirely consistent
> with the capture*: there the field was `0xac101912`, which is exactly
> `172.16.25.18` — the configured `AggregationServerTunIP`, while the client's
> own tun0 was `172.16.25.19`. ZTE's dispatch evidently assigns a device's id
> and its tun address consistently, so the two are equal on a real device and no
> amount of staring at the pcap could have separated them. Running the binary
> with the two set to *different* values was the only thing that could.

The client writes it with `htonl(...)`, i.e. network order. ZTE's real
concentrator writes the same value **byte-reversed**, which is only possible if
the server stores it as a native host-order `u32` — and the client evidently
does not care. So a replacement concentrator may echo it in either order, or
echo whatever the client sent. **PROVEN** (both byte orders present in the same
capture; no comparison against it exists in any receive path read so far).

Because the id equals the tun address on a dispatched device, `icgd` still
renders it as a dotted quad in logs and in the API — it is the readable form of
the value there. That is a logging convenience, not a claim about the field.

### What the sub-header `seq` field means, per type — **PROVEN**

It is a single 4-byte big-endian slot reused for three different purposes, which
is easy to get wrong:

| type | `seq` holds |
|-----:|---|
| 0 (UDP) | the global **UDP sequence number** |
| 1 (ICMP) | always 0 — ICMP is not sequenced |
| 2 / 6 (TCP) | a **CRC32**, not a sequence number. The TCP sequence number lives in the payload at offset 0, little-endian. |
| 3 (handshake) | always 0 |
| 4 (ACK / retransmit) | the sequence number being acknowledged or requested |
| 7 (sequence resync) | the sender's current sequence position |

Note there is **no checksum over the frame and no cryptography anywhere** — the
only "authentication" is the 4-byte magic (the type-2/6 CRC32 covers the payload,
not the frame). Confirmed independently by the RE: the data plane imports no
crypto symbols at all.

---

## 3. Type table — **PROVEN**

From `handle_recv_packet` at `0x24b4c` — the client's receive dispatcher, a
plain switch on `body[4]`:

| type | client-side handler | carries | seen in capture |
|-----:|---|---|---|
| 0 | `handle_recv_udp_packet` (`0x29728`) | tunnelled UDP — a whole raw IPv4 packet | no (builder is `process_up_udp_packet`, `0x295c4`) |
| 1 | `handle_recv_icmp_packet` (`0x160e4`) | tunnelled ICMP — a whole raw IPv4 packet | yes, both directions |
| 2 | `handle_recv_tcp_packet` (`0x1e670`) | TCP data, **server → client** | yes |
| 3 | `handle_recv_handshake_packet` (`0x1a06c`) | handshake, keepalive, UDP RTT sync | yes |
| 4 | `handle_server_ack_packet` (`0x1a1a4`) | ACKs, retransmit requests, telemetry | yes |
| 5 | — logged as unknown and dropped | — | no |
| 6 | — dropped by the client | TCP data, **client → server** | yes |
| 7 | `handle_sort_sync_packet` (`0x13c5c`) | global sequence resynchronisation | no |

The TCP data direction is asymmetric on purpose: the client *sends* type 6 and
*receives* type 2. Type 0 (UDP) and type 1 (ICMP) use the same number in both
directions. A concentrator must therefore accept type 6 and emit type 2.

---

## 4. type 3 — handshake / keepalive / RTT — **PROVEN**

`opcode` indexes this enum. Recovered from the `const char*` table at file
`0x500a0`, and confirmed by `handle_recv_handshake_packet` doing
`ubfiz x0, opcode, 3, 3` to index it.

| opcode | name | direction | payload |
|------:|---|---|---|
| 0 | `ICG_KEEPALIVE` | client → server | 84-byte fake IPv4/ICMP ping (§4.2) |
| 1 | `ICG_HANDSHAKE_REQ_WITH_CONFIG` | client → server | 50-byte device/config struct (§4.1) |
| 2 | `ICG_CONFIRM_SERVER_ACK` | client → server | 84-byte fake IPv4/ICMP ping (§4.2) |
| 3 | `ICG_SERVER_HANDSHAKE_ACK` | server → client | **ignored by the client** |
| 4 | `HANDSHAKE_CODE_RESREVER` (sic) | — | reserved, unused |
| 5 | `ICG_UDP_CHNN_RTT_SYNC` | client → server | 25-byte RTT struct (§4.3) |
| 6 | `ICG_UDP_CHNN_RTT_SYNC_ACK` | server → client | 25-byte RTT struct (§4.3) |
| 7 | `ICG_UDP_CHNN_RTT_ACK` | client → server | 25-byte RTT struct, echoed verbatim |

`seq` in the sub-header is 0 for all type-3 frames.

### 4.1 `ICG_HANDSHAKE_REQ_WITH_CONFIG` body — **PROVEN**

Built inline in `send_handshake_pkt_directly` (`0x10e2c`, which inlines
`makeup_handshake_with_config_pkt` and `get_netcard_info`).
`body_length = 60` → payload 50 bytes, frame 68 bytes.

Every 4-byte field goes through `htonl()`, so the payload is big-endian
throughout. `cfg` is the global config struct (vaddr `0xf83898`).

| off | size | content |
|----:|-----:|---|
| 0 | 4 | WLAN MAC bytes 0–3 (`ioctl SIOCGIFHWADDR`) |
| 4 | 2 | WLAN MAC bytes 4–5 |
| 6 | 4 | `inet_addr(cfg+0x94)` — the local tun IP string |
| 10 | 4 | `htonl(0)` — constant zero |
| 14 | 4 | not written by the observed path (**INFERRED**: left zero by `memory_malloc`, or set by the helper at `0x10cd4`) |
| 18 | 4 | `htonl(cfg[0x134])` |
| 22 | 4 | `htonl(cfg[0x138])` |
| 26 | 4 | `htonl(cfg[0x13c])` |
| 30 | 4 | `htonl(u16 @ helper+2)` |
| 34 | 4 | `htonl(u16 @ helper+0)` |
| 38 | 4 | `htonl(cfg[0x140])` |
| 42 | 4 | `htonl(u32 @ hwinfo+8)` |
| 46 | 4 | `htonl(cfg[0x144])` |

The identity is the MAC — the same `icgmac` the MQTT control plane uses. The
`cfg[0x134..0x144]` block is device/config telemetry whose individual meanings
are **not yet mapped** (they are populated by `init_config_from_local` /
`init_device_local_args` from `icg.conf`). **A concentrator does not need to
parse any of it** — see §6.

### 4.2 The "fake ping" payload — **PROVEN**

`ICG_KEEPALIVE` and `ICG_CONFIRM_SERVER_ACK` both carry a synthesised IPv4 +
ICMP echo request, built by `create_ipicmp_packet` (`0x1bf1c`), which returns
`0x54` = 84 bytes. `body_length = 94`, frame 102.

```
IPv4 (20 bytes)                       ICMP (64 bytes)
  0x45 0x00                             type 8, code 0
  total length 0x0054 (BE)              checksum
  id 0, frags 0                         id  = htons(getpid() & 0xffff)
  TTL 0xff, proto 1 (ICMP)              seq = htons(g_icmp_seq++)
  checksum                              data[0..5] = 02 04 <tunnel_id> 00 00 00
  src = local tun IP (cfg+0x94)         data[6..55] = 0xa5 filler
  dst = 8.8.8.8 (hardcoded string)
```

`fill_tunnel_id_report` (`0x10ce4`) writes the `02 04 <tid> 00 00 00` prefix
into the ICMP data area, so a concentrator can recover which WAN leg sent a
keepalive from `payload[28]`. **INFERRED**: the `02 04` prefix is a TLV header
(`type=2, len=4`) around a u32 LE tunnel id — the shape fits and the observed
tunnel ids (4, 5, 9, 13, 1) are all `< 16`, but no TLV parser was located.

Sample from the capture (`tcp 3/0`, body 94):

```
4500 0054 0000 0000 ff01 e675 ac101913 08080808
0800 5d85 74cf 078d  02 04 05 00 00 00  a5a5a5a5 ...
                          ^^ tunnel id 5
```

Note `8.8.8.8` and TTL 255 are constants — these frames are **not** real pings
and are never forwarded; the concentrator should treat them purely as
liveness/handshake signals.

### 4.3 UDP channel RTT sync body — **PROVEN**

25-byte struct, `body_length = 35`, frame 43. Built by
`makeup_chnn_rtt_refresh_packet` (`0x309bc`) which copies the struct verbatim;
parsed by `update_chnn_rtt_and_response_ack` (`0x30d9c`).

| off | size | field |
|----:|-----:|---|
| 0 | 4 | `seq` (u32 **LE**) |
| 4 | 4 | client timestamp, **high** 32 bits (u32 LE) |
| 8 | 4 | client timestamp, **low** 32 bits (u32 LE) |
| 12 | 4 | server timestamp, high 32 bits (u32 LE) |
| 16 | 4 | server timestamp, low 32 bits (u32 LE) |
| 20 | 5 | trailer, observed constant `04 01 01 00 00` |

The timestamps are **milliseconds since the Unix epoch in a 64-bit value split
into two little-endian 32-bit words, high word first** — proven by
`0x30dfc..0x30e18`:

```
ldp w26, w25, [x23]        ; w26 = seq, w25 = payload[4]  (high)
ldr w0,  [x23, 8]          ; w0  = payload[8]             (low)
orr x25, x0, x25, lsl 32   ; client_ms = (high << 32) | low
```

Verified numerically: `hi=416, lo=0x2fdcb432` → 1 787 509 093 938 ms →
2026-08-22, which matches the capture date. The client then does
`gettimeofday()` and computes `rtt_ms = now_ms - client_ms`, compares it
against `cfg[0x14c]`, and feeds `set_udp_tunnel_rtt(tunnel, rtt)` — which is
what drives per-WAN send scheduling.

Exchange, per UDP leg, roughly every 500 ms in the capture:

```
client --(op 5, client_ts set, server_ts zero)--> server
client <--(op 6, client_ts echoed, server_ts filled)-- server
client --(op 7, entire 25 bytes echoed byte-for-byte)--> server
```

**The op-7 frames in the capture are byte-identical to the op-6 frames that
preceded them** except for the opcode byte. So the server must echo
`payload[4..11]` unchanged — that is the only field the RTT calculation
depends on.

The trailer's meaning is **unmapped**; it is identical (`04 01 01 00 00`) on
both WAN legs, so it is not a per-leg index. Echoing it is sufficient.

---

## 5. type 4 — ACKs, retransmit requests, telemetry — **PROVEN**

`handle_server_ack_packet` (`0x1a1a4`) switches on `opcode`; opcodes 5, 9 and
15 are enqueued and later handled by `handle_misc_packet` (`0x11920`).

| opcode | name | direction | body |
|------:|---|---|---|
| 2 | `UDP_REQUEST_TRANS_RANGE` | both | seq list, §5.1 — **PROVEN** (`0x29a2c`) |
| 3 | `TCP_REQUEST_TRANS_RANGE` | both | seq list, §5.1 — **PROVEN** (`0x1f484`) |
| 4 | `TCP_REQUEST_TRANS` (single) | server → client | empty; seq in sub-header (**INFERRED** — no builder found in the client, so this may be server-only) |
| 5 | `TCP_ACCUMU_ACK` | both | empty; cumulative seq in sub-header — **PROVEN** |
| 8 | `UDP_REQUEST_TRANS` (single) | client → server | empty; seq in sub-header — **PROVEN** (`0x29bcc`) |
| 9 | `UDP_ACCUMU_ACK` | both | empty; cumulative seq in sub-header — **PROVEN** |
| 11 | server-config report | client → server | 4-byte body — **PROVEN** |
| 12 | card-priority table report | client → server | `2 * (n + 4)` bytes — **PROVEN** |
| 13 | card-status table report | client → server | `8 + 12*n` bytes — **PROVEN** |
| 14 | speed-limit table report | client → server | `4 + 8*n` bytes — **PROVEN** |
| 15 | tunnel detect / probe | server → client | empty; client only logs it — **PROVEN** |

Opcodes 0, 1, 6, 7 and 10 are unused: `handle_server_ack_packet` logs
`[ACK] fd: %d recv error ack packet type: %d` for anything not in the table.

Names come from the log strings (`[TCPDL][TCP ACK] SEND TCP_ACCUMU_ACK
tcpseq: %u`, `[TCP REQ RETRAN][RECV] TCP_REQUEST_TRANS_RANGE num: %d`,
`[TUNNEL] fd: %d recv tunnel detect pkt`, …).

**Cumulative ACK** (`makeup_seq_ack_packet`, `0x10aec`): `body_length = 10`,
frame 18, no payload, `seq` = the cumulative sequence number, network order.
In the capture the server ACKed every 100 packets (`23900, 24000, 24100 …`).
The client sends the same shape with opcode 5 (TCP) or 9 (UDP).

**Telemetry** rides type 4 as well. `makeup_report_msg_packet(opcode, body,
len)` (`0x11cbc`) hardcodes `type = 4` and takes the opcode as its first
argument; the four callers pass:

| caller | opcode | body length |
|---|------:|---|
| `report_server_config_to_server` (`0x12a5c`) | 11 | 4 |
| `report_priority_table_to_server` (`0x12408`) | 12 | `2 * (n + 4)` |
| `report_status_table_to_server` (`0x1205c`) | 13 | `8 + 12*n` |
| `report_speed_table_to_server` (`0x12864`) | 14 | `4 + 8*n` |

where `n` is the number of table entries. The body layouts are **not mapped**;
a concentrator should log and discard them. None of these appeared in the
capture.

### 5.1 `*_REQUEST_TRANS_RANGE` body — **PROVEN** for TCP

`makeup_tcp_req_retran_packet` (`0x1f484`). Fixed 204-byte payload,
`body_length = 214`, frame 222. All values big-endian.

```
+0        u32 BE   count  (number of valid entries, max 50)
+4        u32 BE   seq[0]
+8        u32 BE   seq[1]
...
+4+4*49   u32 BE   seq[49]        (unused entries are zero)
```

The sub-header `seq` equals `seq[0]`. The builder always `memcpy`s the full
`0xcc` = 204 bytes regardless of `count`, so trailing entries are zero padding.
Confirmed against the capture: every `tcp 4/3` frame is exactly 214 body bytes
with `count = 0x32 = 50` and a run of consecutive sequence numbers.

`makeup_udp_req_retran_range_packet` (`0x29a2c`) is instruction-for-instruction
the same builder with `0x204` (type 4 / opcode 2) instead of `0x304`: same
`memset` of `0xc8`, same count-first array, same `memcpy` of `0xcc`. So the UDP
variant is **identical**, over the UDP sequence space. **PROVEN**.

---

## 6. Handshake state machine — **PROVEN**

Three functions:

- `icg_handshake_proc` (`0x11504`) — the driver thread, 1 Hz.
- `update_icg_proxy_state` (`0x13e0c`) — the state transition on receive.
- `refresh_icg_resource` (`0x12cf8`) — the reset that ICG_SERVER_HANDSHAKE_ACK triggers.

States (name table at file `0x50088`): `0 ICG_INIT_STATE`,
`1 ICG_SERVER_READY`, `2 ICG_AND_SRV_BOTH_OK`.

```
                    +-----------------+
   boot ----------->| ICG_INIT_STATE  |
                    +-----------------+
                       |  every 1 s: send_handshake_pkt_directly()
                       |  -> type 3 / opcode 1 on EVERY valid TCP tunnel
                       v
        server replies type 3 / opcode 3
        update_icg_proxy_state(): state 0 -> 1
        refresh_icg_resource(pkt, 3):
            reset_send_stash_record()
            reset_icg_sort_modules()
            reset udp sort/channel modules
                       |
                       v
                    +-------------------+
                    | ICG_SERVER_READY  |
                    +-------------------+
                       |  send_handshake_rsp_pkt_directly()
                       |  -> type 3 / opcode 2 on EVERY valid TCP tunnel
                       |  on success:
                       v
                    +----------------------+
                    | ICG_AND_SRV_BOTH_OK  |  uci zwrt_router.tmp_router
                    +----------------------+       .icg_agg_status = 1
                       |
                       |  steady state: type 3 / opcode 0 keepalives per
                       |  tunnel, UDP RTT sync 5/6/7 per UDP leg, data flows
```

### What the server must actually do

This is the important result, and it is unusually forgiving:

1. **`ICG_SERVER_HANDSHAKE_ACK` content is never parsed.** `refresh_icg_resource`
   receives `(pkt, opcode)`, checks `opcode == 3`, and if so does nothing with
   the packet but reset local state. The 50-byte config the client sent in
   opcode 1 is **not** echoed, checked, or acknowledged field-by-field. A body
   of exactly the 10-byte sub-header (`body_length = 10`) with
   `type = 3, opcode = 3` is sufficient.
2. **Any type-3 opcode other than 6 advances the state** while in
   `ICG_INIT_STATE` — `update_icg_proxy_state` does not check which. But only
   opcode 3 makes `refresh_icg_resource` do the reset; anything else logs
   `refresh icg resource get error opcode:%d`. So send opcode 3.
3. **Once in `ICG_AND_SRV_BOTH_OK`, later handshake packets are ignored**
   (`[ICG STATE] ignore oper: %s(%u) unhandle icg state:%s`). The transition is
   one-way until `icg_release_resource` runs.
4. **The client sends the handshake on every tunnel** and will accept the ACK
   on any one of them, since state is global rather than per-tunnel.

### Liveness the server must not neglect — **PROVEN**

`device_zombie_state_check` (`0x144fc`), driven by `icg_timer_process`, compares
`now_ms` against a global last-activity timestamp (a `timeval` at `0xf83ae0`,
read under a mutex by `0x10c5c`) and acts on three hardcoded thresholds:

| idle | action |
|---|---|
| `> 300 000 ms` (`0x493e0`) | dismissed as a clock jump — `icg idle for %d(ms) is too large, wait sntp sync!!!`, nothing happens |
| `> 30 000 ms` (`0x7530`) **and** state == `ICG_AND_SRV_BOTH_OK` | `icg_release_resource()` — destroys all tunnels, resets both sort modules, state returns to `ICG_INIT_STATE` and the handshake restarts |
| `> 150 000 ms` (`0x249f0`) | the hard stop: `zte_key_syslog_append`, `icg_agg_status = -4`, `system("/etc/init.d/zte_icg_agg_init stop &")` |

So **a concentrator has a 30-second budget**. Go quiet for longer and the client
tears the session down and re-handshakes; go quiet for 150 s and it stops the
daemon outright, which on an `SMULTIWAN` box means the LAN loses its gateway.

The 300 s escape hatch exists because the device's clock jumps when NTP first
syncs after boot; it is not a grace period you can rely on.

Observed cadences in the capture (which spans only ~8.5 s of a loaded session,
so treat these as steady-state rates, not as a schedule):

| frame | from | rate |
|---|---|---|
| type 3 / op 0 keepalive | client | ~1 Hz per TCP tunnel |
| type 4 / op 15 tunnel detect | server | ~0.6 Hz per TCP tunnel |
| type 4 / op 5 cumulative ACK | server | every 100 sequence numbers (~1.4 s under load) |
| type 3 / op 5,6,7 RTT sync | both | ~20 Hz per UDP leg |

The server's tunnel-detect frames are the obvious keepalive-from-the-server
mechanism; a concentrator should emit them per tunnel at ~1 Hz. **INFERRED**:
that the last-activity timestamp is refreshed by any received frame — the setter
at `0x10c04` was located but its call sites were not enumerated.

---

## 7. type 6 / type 2 — TCP data — **PROVEN**

The transparent-proxy payload. `type 6` client → server, `type 2` server →
client; identical body layout. Built by `makeup_tcp_sync_packet` (`0x190c4`),
`makeup_tcp_disconnect_packet` (`0x170b4`), the payload path inside
`handle_proxy_pld_event` (`~0x175a0`), and `makeup_tcp_block_packet` (inlined
into `proxy_fd_monitor_proc` at `0x18c64`). The common header filler is
`fcn.1e4ac`, which hardcodes `type = 6, opcode = 0`.

```
off  size  endian  field
---  ----  ------  -----------------------------------------------
  0     4  LE      global TCP sequence number (see §9)
  4     2  LE      tcp_optcode
  6     4  BE      original source IP
 10     4  BE      original destination IP
 14     2  BE      original source port
 16     2  BE      original destination port
 18   ...  --      TCP stream data (up to 1400 bytes; MSS is clamped to 1400)
```

The 5-tuple is the **original LAN client's**, which is what makes the
transparent proxy work: the client DNATs LAN TCP to
`<AggregationServerTunIP>:14000`, recovers the real destination with
`SO_ORIGINAL_DST`, and ships the tuple in every frame. The tuple is stored
sender-relative, i.e. on the downlink the server swaps src/dst.

`tcp_optcode`:

| value | meaning | evidence |
|------:|---|---|
| 0 | connect / open the upstream socket | **PROVEN** — `makeup_tcp_sync_packet` writes `strh wzr, [payload, 4]`; observed with an empty body |
| 1 | disconnect / peer closed | **PROVEN** — `makeup_tcp_disconnect_packet` writes 1; observed with an empty body |
| 3 | payload | **PROVEN** — `handle_proxy_pld_event` sets `w3 = 3` before the store; observed with data |
| 4 | flow-control: block (stop sending) | **INFERRED** — `proxy_fd_monitor_proc` stores 4 into the per-fd state at `+0x78` on the "request block!!!" path and later loads it as the optcode |
| 5 | flow-control: unblock | **INFERRED** — the same state is set to 5 on the sibling path |

Unknown optcodes are dropped by the client with
`[TCPDL][PROXY] fd: %d get unknow tcp optcode: %d packet.drop`.

### The sub-header `seq` on TCP data frames is a CRC32

`fcn.1e4ac(hdr, value)` writes `htonl(value)` into the sub-header `seq` field,
and `makeup_tcp_sync_packet` passes it the result of `crc32` (the binary's one
exported symbol, at `0xae9c`) — not a sequence number. The real sequence
number is in the *payload* at offset 0. This is gated by `TcpUpCrcSwitch` /
`TcpDownCrcSwitch` in `icg.conf`.

Consistent with the capture: uplink `type 6` frames carry pseudo-random `seq`
values (`1670417337`, `811899440`, `4255751918`, …) while downlink `type 2`
frames carry `seq = 0`, i.e. ZTE's own server does **not** compute the downlink
CRC. **INFERRED**: the client does not verify it either — no CRC comparison was
located in `handle_recv_tcp_packet`, but that function has not been read line
by line yet. A replacement concentrator should send 0 and see whether anything
complains.

Capture sample (uplink `type 6`, body 28, no data — a connect):

```
025d0000  0000  c0a800f5  0dd406ba  f4ed  2766
seq=23810 opt=0 192.168.0.245 -> 13.212.6.186 :62701 -> :10086
```

and the matching downlink `type 2` (body 28, opt 1 — a close) with the tuple
swapped.

---

## 8. type 0 / type 1 — tunnelled UDP and ICMP — **PROVEN**

These two are much simpler than TCP: there is no 5-tuple field and no proxy,
because UDP and ICMP are not proxied at all. They ride `tun0`, so the payload is
**a complete raw IPv4 packet**, verbatim, starting at the version/IHL byte —
exactly the bytes `tun_read_process` read from the tun device.

| type | builder | sub-header `seq` | payload |
|-----:|---|---|---|
| 0 | `process_up_udp_packet` (`0x295c4`) | global UDP sequence number, `htonl` | raw IPv4/UDP packet |
| 1 | (ICMP tunnel builder, `0x16070`) | always 0 — unsequenced | raw IPv4/ICMP packet |

Both use `opcode = 0` in both directions, and both set
`body_length = payload_len + 10`.

This corrects an earlier reading of this document, which guessed a TCP-like
`{seq, srcip, dstip, sport, dport}` header for type 0. The two `inet_ntop`
calls in `handle_recv_udp_packet` that suggested it are at payload **+12** and
payload **+16** — which are simply the source- and destination-address fields
of the IPv4 header:

```
process_up_udp_packet (send side, payload at pkt+0x11a):
    inet_ntop(AF_INET, pkt+0x126, ...)   ; payload + 12 -> IPv4 saddr
    inet_ntop(AF_INET, pkt+0x12a, ...)   ; payload + 16 -> IPv4 daddr
handle_recv_udp_packet (recv side, payload at pkt+0x112):
    inet_ntop(AF_INET, pkt+0x11e, ...)   ; payload + 12 -> IPv4 saddr
    inet_ntop(AF_INET, pkt+0x122, ...)   ; payload + 16 -> IPv4 daddr
```

Both sides agree, and both are just decoding the encapsulated header for the
`[UDPUL] process upload data [%s->%s] udpseq: %u` /
`[UDPDL] server->icg udp packet [%s->%s] udpseq: %u` log lines.

The sequence number is confirmed to live in the sub-header rather than the
payload: `process_up_udp_packet` does `stur htonl(pkt->seq), [hdr+6]`, and on
receive `handle_recv_packet` unconditionally stores `ntohl(body+6)` into
`pkt+0x50`, which is exactly the field `handle_recv_udp_packet` then logs as
`udpseq`.

### What this means for a concentrator

The UDP and ICMP legs need the concentrator to behave like a router, not a
proxy: allocate a tun device (or a raw socket), write decapsulated packets to
it, SNAT the tun subnet outbound, and re-encapsulate replies. Only TCP needs
the userspace proxy and the 5-tuple handling of §7. UDP still needs the global
sequence space, reordering and retransmission; ICMP needs none of it.

Neither type appeared with real traffic in the capture other than user pings to
`8.8.8.8` (type 1) — the UDP legs carried only RTT sync during that window — so
the *behaviour* under loss is unverified even though the format is proven.

## 9. type 7 — global sequence resynchronisation — **PROVEN** (numbering)

`makeup_sync_packet(oper)` (`0x13b44`) writes `type = 7, opcode = oper`,
`body_length = 10`, frame 18 — no payload; the sequence lives in the
sub-header. `handle_sort_sync_packet` (`0x13c5c`) dispatches:

| opcode | meaning | client action |
|------:|---|---|
| 6 | TCP sort sync **request** | `process_server_tcp_sort_sync_request` |
| 7 | TCP sort sync **ack** | accepted and freed, no handler |
| 10 | UDP sort sync **request** | `process_server_udp_sort_sync_request` |
| 11 | UDP sort sync **ack** | accepted and freed, no handler |

Anything else logs `[SEQ SYNC] recv error sync optcode %d`.

`makeup_udp_sort_sync_packet` (`0x2d998`) writes `0xa07` (type 7 / opcode 10,
body 10) and `makeup_udp_sort_sync_ack_packet` (`0x2da88`) writes `0xb07`
(type 7 / opcode 11, body **18**, i.e. 8 bytes of payload whose layout has
**not** been read). The TCP equivalents go through `makeup_sync_packet` with
oper 6 / 7 and carry no payload.

Purpose: when a receiver's reorder buffer stalls (`[TCPDL][SEQ SYNC] notice
tcpseq: %u blocked %d ms ... start seq sync`) it asks the peer to declare its
current sequence position so the hole can be skipped rather than waited on
forever. A minimal concentrator can answer a sync request by simply
acknowledging its own current position, and can ignore acks.

---

## 10. Sequence spaces and reliability — how the two ends must agree

Two **global** sequence counters per direction, shared across all WAN legs —
one for TCP (`src/tcp/tcp_up_seq.c`, `tcp_sort.c`) and one for UDP
(`src/udp/udp_up_seq.c`, `udp_chan_sort.c`). This is the whole point of ICG: a
packet is assigned the next global sequence number, then dispatched over
*whichever* leg looks best, and the receiver reassembles in order.

Observed and read:

- Sequence numbers are **u32 LE in the payload** for data frames (§7, §8) and
  **u32 BE in the sub-header** for control frames (ACKs, retransmit requests).
  Both refer to the same number space. Cross-checked in the capture: uplink
  data carried `0x5d02..0x5d08` LE in the payload, and the server's retransmit
  requests referenced `0x5d08..0x5d5f` BE — the same run.
- Send-leg selection is by RTT and backlog (`TcpTunnelSelectModel=2`
  min-RTT-range, `TcpTunnelValidRtt=1000`), fed by the §4.3 RTT sync and
  `get_min_tcp_tunnel_rtt` / `get_udp_tunnel_min_rtt`.
- Receive side stashes out-of-order packets (`stash_and_sort_tcp_packet`,
  `pick_all_ready_tcp_packet`), tracks holes (`src/udp/udp_retran_tbl.c`),
  requests selective retransmission (§5.1), and smooths jitter over a dynamic
  5→300 ms window.
- Cumulative ACKs (§5, opcode 5/9) let the sender free its retransmit stash;
  ZTE's server sent one per 100 packets.
- Optional FEC exists (`FECCommonNum=5`, `FECFECNum=1`) but is **off** and no
  FEC frame type was identified.

---

## 11. Complete recovered-symbol index

Useful entry points, for picking this back up. All are file offsets; feed them
to `research/tools/icg/dis.py`.

| addr | function | role |
|---|---|---|
| `0x24b4c` | `handle_recv_packet` | **the type dispatcher** (§3) |
| `0x2442c` | `recv_tcp_stream` | framing / resync on the TCP leg |
| `0x30288` | `handle_udp_stream_recv` | framing on a UDP leg (`recv identify:0x%x error`) |
| `0x1a06c` | `handle_recv_handshake_packet` | type 3 in |
| `0x1a1a4` | `handle_server_ack_packet` | type 4 in |
| `0x11920` | `handle_misc_packet` | type 4 opcodes 5 / 9 / 15 |
| `0x13c5c` | `handle_sort_sync_packet` | type 7 in |
| `0x1e670` | `handle_recv_tcp_packet` | type 2 in |
| `0x29728` | `handle_recv_udp_packet` | type 0 in |
| `0x160e4` | `handle_recv_icmp_packet` | type 1 in |
| `0x11504` | `icg_handshake_proc` | **state machine driver** (§6) |
| `0x13e0c` | `update_icg_proxy_state` | state transition |
| `0x12cf8` | `refresh_icg_resource` | ACK-triggered reset |
| `0x10e2c` | `send_handshake_pkt_directly` | builds type 3 / opcode 1 |
| `0x112a0` | `send_handshake_rsp_pkt_directly` | builds type 3 / opcode 2 |
| `0x10d74` | `makeup_tunnel_keepalive_packet` | builds type 3 / opcode 0 |
| `0x309bc` | `makeup_chnn_rtt_refresh_packet` | builds type 3 / opcode 5,6,7 |
| `0x30d9c` | `update_chnn_rtt_and_response_ack` | parses RTT sync (§4.3) |
| `0x10aec` | `makeup_seq_ack_packet` | builds type 4 / opcode 5,9 |
| `0x1f484` | `makeup_tcp_req_retran_packet` | builds type 4 / opcode 3 (§5.1) |
| `0x29a2c` | `makeup_udp_req_retran_range_packet` | builds type 4 / opcode 2 |
| `0x29bcc` | `makeup_udp_req_retran_packet` | builds type 4 / opcode 8 |
| `0x11cbc` | `makeup_report_msg_packet` | builds type 4 / telemetry opcodes |
| `0x190c4` | `makeup_tcp_sync_packet` | type 6, tcp_optcode 0 |
| `0x170b4` | `makeup_tcp_disconnect_packet` | type 6, tcp_optcode 1 |
| `0x18c64` | `proxy_fd_monitor_proc` | inlines `makeup_tcp_block_packet` |
| `0x1e4ac` | (header filler) | writes type 6 / opcode 0 / CRC |
| `0x1bf1c` | `create_ipicmp_packet` | the fake ping (§4.2) |
| `0x10ce4` | `fill_tunnel_id_report` | tunnel id TLV in the fake ping |
| `0x13b44` | `makeup_sync_packet` | type 7 |
| `0x2d998` | `makeup_udp_sort_sync_packet` | type 7 / opcode 10 |
| `0x2da88` | `makeup_udp_sort_sync_ack_packet` | type 7 / opcode 11 |
| `0x25b28` | `send_tunnel_data` | the actual `send()` on a TCP leg |
| `0xae9c` | `crc32` | the only exported symbol |

Data:

| addr | content |
|---|---|
| `0x50048` (vaddr `0x60048`) | handshake opcode name table (variant A) |
| `0x500a0` (vaddr `0x600a0`) | handshake opcode name table used by `handle_recv_handshake_packet` |
| `0x50088` (vaddr `0x60088`) | ICG state name table |
| `0xf83898` | global config struct (`cfg` above) |
| `0x161570` | hardware/device info struct |
| `0x161830` | `g_icg_state` |

---

## 12. What is still missing

Ordered by how much it blocks a working concentrator. The four items that were
blocking as of the first draft are now closed (§5, §6, §8).

**Nothing currently blocks a first implementation.** What remains:

| # | gap | why it matters | how to close it |
|--:|---|---|---|
| 1 | Body layout of the four telemetry reports (type 4, opcodes 11–14) | only so a concentrator can *understand* what the device reports; discarding them is fine | read `assem_status_table_to_net_message` (`0x11f3c`), `assem_table_to_net_message` (`0x12354`), `assem_speed_table_to_net_message` (`0x126c8`), `assem_server_config_to_net_message` (`0x127bc`) |
| 2 | `cfg[0x134..0x144]` fields in `ICG_HANDSHAKE_REQ_WITH_CONFIG` (§4.1), and payload offset 14 | tells us what ZTE's cloud learns about the device; no server-side need | trace `init_config_from_local` / `init_device_local_args` writes into the config struct at `0xf83898` |
| 3 | The 5-byte trailer on the RTT struct (§4.3) | echoing it is sufficient | read `udp_chnn_rtt_proc` (`0x310d4`) |
| 4 | The 8-byte payload of `UDP_SORT_SYNC_ACK` (type 7 / opcode 11) (§9) | needed for full sequence-resync support | read `makeup_udp_sort_sync_ack_packet` (`0x2da88`) |
| 5 | `tcp_optcode` 4/5 (block/unblock) confirmation (§7) | flow control; a concentrator can ignore inbound and never send them | read `proxy_fd_monitor_proc` (`0x18c64`) around `0x18e34`/`0x18ec4` |
| 6 | Whether the client validates the downlink CRC32 (§7) | if it does, the concentrator must compute it | read `handle_recv_tcp_packet` (`0x1e670`) line by line; ZTE's own server sends 0, which is strong evidence it does not |
| 7 | What refreshes the last-activity timestamp (§6) | determines exactly which frames count as liveness | enumerate call sites of the setter at `0x10c04` |
| 8 | `type 5` | unknown; dropped by the client, so server-only or vestigial | grep for a `type = 5` store; none found so far |
| 9 | FEC framing | configured (`FECCommonNum=5`, `FECFECNum=1`) but disabled | may simply not exist in this build |

**Behavioural unknowns — these need traffic, not disassembly.** The capture is
only ~8.5 s long and contained no tunnelled UDP data, no packet loss worth
speaking of, no sequence resync, and no flow control. So while the *formats* are
proven, the *protocol dynamics* are not observed:

- how the peer is expected to respond to a retransmit request it cannot satisfy
- what triggers sequence resync in practice, and what the correct reply is
- whether cumulative ACKs are required or merely an optimisation
- block/unblock semantics and timing
- behaviour when a WAN leg disappears mid-flow

Getting those means a longer capture under load, which means re-enabling
`SMULTIWAN` against ZTE's cloud — with the operational hazards spelled out in
[`OPERATING.md`](OPERATING.md), on a device that is someone's only gateway. **Ask first.**
The alternative, and probably the better one, is to implement against the proven
formats and discover the dynamics by testing against the real client with our
own concentrator, where a failure costs a re-handshake rather than the operator's
internet.
