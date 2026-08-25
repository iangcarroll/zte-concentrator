IMAGE  ?= zte-emu
BLOB   ?= blobs/zte_icg_agg

# Where the decryption key lives locally. Gitignored twice over (by
# blobs/.gitignore's catch-all and by name in the root .gitignore). If it is
# present, encrypt/decrypt use it, so there is no need to keep a copy in /tmp
# or to paste the key into a shell. $ICG_BLOB_KEY still wins if set, which is
# how CI supplies it.
KEYFILE ?= blobs/icg_blob_key

# The concentrator as seen from inside the container. 172.17.0.1 is the default
# bridge gateway on Linux; Docker Desktop also resolves host.docker.internal.
SERVER_IP ?= 172.17.0.1
TCP_PORT  ?= 10088
UDP_BASE  ?= 10000

IMAGE_REMOTE ?= ghcr.io/iangcarroll/zte-concentrator/emu:main

.PHONY: build pull run shell imports contract encrypt decrypt keygen clean

build:
	docker build --platform linux/arm64 -t $(IMAGE) .

# Prefer this to `build`: CI has already built it, and building locally means
# installing a compiler into an aarch64 image, which is slow on a bad link.
pull:
	docker pull --platform linux/arm64 $(IMAGE_REMOTE)
	docker tag $(IMAGE_REMOTE) $(IMAGE)

# NET_ADMIN for the dummy links and iptables; /dev/net/tun for the UDP/ICMP path.
run:
	@test -f $(BLOB) || { echo "no $(BLOB) — run 'make decrypt', or see README"; exit 2; }
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

# --- the encrypted blob -----------------------------------------------------
# The binary is ZTE's, so the repo holds only ciphertext; the key lives in the
# ICG_BLOB_KEY Actions secret and in your password manager. See README.
# Recipes cd to the repo root first (the module root), so this path is
# relative to there, not to emu/.
CRYPT = go run ./emu/blobcrypt

keygen:
	@cd .. && $(CRYPT) -keygen

# Both targets take the key from $ICG_BLOB_KEY if it is set, otherwise from
# $(KEYFILE) on stdin, otherwise blobcrypt prompts. Piping the file avoids
# putting the key in the environment or in shell history.
encrypt:
	@test -f $(BLOB) || { echo "no plaintext at $(BLOB)"; exit 2; }
	@cd .. && if [ -n "$$ICG_BLOB_KEY" ]; then \
		$(CRYPT) -e -in emu/$(BLOB) -out emu/$(BLOB).enc; \
	elif [ -f emu/$(KEYFILE) ]; then \
		$(CRYPT) -e -in emu/$(BLOB) -out emu/$(BLOB).enc < emu/$(KEYFILE); \
	else \
		$(CRYPT) -e -in emu/$(BLOB) -out emu/$(BLOB).enc; \
	fi
	@echo "wrote $(BLOB).enc — commit that, never $(BLOB)"

decrypt:
	@test -f $(BLOB).enc || { echo "no $(BLOB).enc to decrypt"; exit 2; }
	@cd .. && if [ -n "$$ICG_BLOB_KEY" ]; then \
		$(CRYPT) -d -in emu/$(BLOB).enc -out emu/$(BLOB); \
	elif [ -f emu/$(KEYFILE) ]; then \
		$(CRYPT) -d -in emu/$(BLOB).enc -out emu/$(BLOB) < emu/$(KEYFILE); \
	else \
		echo "no $$ICG_BLOB_KEY and no $(KEYFILE); blobcrypt will ask"; \
		$(CRYPT) -d -in emu/$(BLOB).enc -out emu/$(BLOB); \
	fi
	@chmod 700 $(BLOB)
	@echo "wrote $(BLOB) (gitignored)"

clean:
	docker rmi $(IMAGE) 2>/dev/null || true
