# A minimal stand-in for the MU5252's userland, just enough to run the real
# zte_icg_agg against a concentrator.
#
# Alpine because the device is musl (its loader is /lib/ld-musl-aarch64.so.1),
# and aarch64 because the device is — which on an Apple Silicon or arm64 host
# means this runs natively with no emulation at all.
#
# The proprietary binary is NOT baked in. Mount it at /opt/icg/zte_icg_agg.

FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev
COPY shim.c /src/shim.c
RUN gcc -shared -fPIC -O2 -o /libzteshim.so /src/shim.c

FROM alpine:3.20
# Deliberately no apk install in the runtime stage. Everything needed is either
# in busybox or unnecessary:
#   * libgcc_s.so.1 is a DT_NEEDED entry, but the only symbols the binary wants
#     from it (__register_frame_info, __deregister_frame_info) are WEAK, so the
#     loader tolerates them being absent — it is symlinked to the shim below
#     purely so the file exists.
#   * busybox provides ip, ifconfig, route and sysctl, which is what the
#     binary shells out to.
# Everything else the binary shells out to is in busybox.
# The binary shells out to iptables and to `ip`, and busybox's `ip` cannot do
# rules or dummy links properly. binutils gives CI the `nm` it uses to assert
# the shim still covers every import.
#
# Pass EXTRA_PKGS="" to build with no package installs at all — useful on a
# connection too poor for apk, at the cost of the transparent-proxy path.
ARG EXTRA_PKGS="binutils iptables iproute2"
RUN if [ -n "$EXTRA_PKGS" ]; then apk add --no-cache $EXTRA_PKGS; fi

COPY --from=build /libzteshim.so /usr/lib/libzteshim.so

# Every DT_NEEDED entry zte_icg_agg carries. It imports six non-libc symbols in
# total, all of them in the shim, so pointing all of these at the shim satisfies
# the loader. Nothing here is a reimplementation of ubus, uci, sqlite or
# mbedtls; the binary never calls into them directly.
RUN set -eu; \
    for so in libzlog.so.1.2 libzterouter.so libubus.so.20230605 libuci.so \
              libjson-c.so.5 libsqlite3.so.0 libztelog.so libzteescape.so \
              libzteencrypt.so libmbedcrypto.so.16 libztecrypto.so \
              libztecryptofilewrapper.so libcares.so.2; do \
      ln -sf /usr/lib/libzteshim.so "/usr/lib/$so"; \
    done; \
    ln -sf /usr/lib/libzteshim.so /usr/lib/libgcc_s.so.1

COPY etc/ /etc/zteshim/
COPY home-icg/ /home/icg/
COPY entrypoint.sh /entrypoint.sh
COPY stubs/ /opt/stubs/
RUN chmod +x /entrypoint.sh /opt/stubs/* && \
    ln -sf /opt/stubs/icg_agg_fw.sh /sbin/icg_agg_fw.sh && \
    mkdir -p /etc/init.d && \
    ln -sf /opt/stubs/zte_icg_agg_init /etc/init.d/zte_icg_agg_init && \
    mkdir -p /logfs /var/run

ENV ZTESHIM_UCI=/etc/zteshim/uci.conf
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
