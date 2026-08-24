IMAGE  ?= zte-emu
BLOB   ?= blobs/zte_icg_agg

# The concentrator as seen from inside the container. 172.17.0.1 is the default
# bridge gateway on Linux; Docker Desktop also resolves host.docker.internal.
SERVER_IP ?= 172.17.0.1
TCP_PORT  ?= 10088
UDP_BASE  ?= 10000

IMAGE_REMOTE ?= ghcr.io/iangcarroll/zte-coord/emu:main

.PHONY: build pull run shell imports contract clean

build:
	docker build --platform linux/arm64 -t $(IMAGE) .

# Prefer this to `build`: CI has already built it, and building locally means
# installing a compiler into an aarch64 image, which is slow on a bad link.
pull:
	docker pull --platform linux/arm64 $(IMAGE_REMOTE)
	docker tag $(IMAGE_REMOTE) $(IMAGE)

# NET_ADMIN for the dummy links and iptables; /dev/net/tun for the UDP/ICMP path.
run:
	@test -f $(BLOB) || { echo "put zte_icg_agg in $(BLOB) first (see README)"; exit 2; }
	docker run --rm -it --platform linux/arm64 \
	  --cap-add NET_ADMIN --cap-add NET_RAW \
	  --device /dev/net/tun \
	  -e SERVER_IP=$(SERVER_IP) -e TCP_PORT=$(TCP_PORT) -e UDP_BASE=$(UDP_BASE) \
	  -e TRACE=$(TRACE) \
	  -v "$(CURDIR)/$(BLOB):/opt/icg/zte_icg_agg:ro" \
	  $(IMAGE)

# Same container, shell instead of the daemon, for poking at it.
shell:
	docker run --rm -it --platform linux/arm64 \
	  --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun \
	  -v "$(CURDIR)/$(BLOB):/opt/icg/zte_icg_agg:ro" \
	  --entrypoint /bin/bash $(IMAGE)

# Re-check the claim the whole approach rests on: six non-libc imports.
imports:
	@test -f $(BLOB) || { echo "put zte_icg_agg in $(BLOB) first"; exit 2; }
	r2 -q -c ii $(BLOB) | awk '{print $$NF}' | sort -u

# Regenerate the CI contract from the real binary.
contract:
	./refresh-contract.sh $(BLOB)

clean:
	docker rmi $(IMAGE) 2>/dev/null || true
