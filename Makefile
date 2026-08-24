VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: all icgd icg-probe test lint deploy clean

all: icgd icg-probe

# The concentrator: the server a ZTE CPE bonds its WANs through.
icgd:
	go build -ldflags="$(LDFLAGS)" -o bin/icgd ./cmd/icgd

# Validates a concentrator by pretending to be a CPE. Speaks the real
# protocol, so a pass means a device would work.
icg-probe:
	go build -ldflags="$(LDFLAGS)" -o bin/icg-probe ./cmd/icg-probe

test:
	go test -race ./...

lint:
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	shellcheck -S warning deploy/icgd-deploy.sh
	shellcheck -s sh deploy/icgd-install.sh

# make deploy HOST=ubuntu@1.2.3.4 [ARGS="--devices aa:bb:cc:dd:ee:ff"]
# Works out clean install vs update by itself; --dry-run to look first.
deploy:
	@test -n "$(HOST)" || { echo 'usage: make deploy HOST=user@server [ARGS="..."]'; exit 2; }
	./deploy/icgd-deploy.sh $(ARGS) $(HOST)

clean:
	rm -rf bin/
