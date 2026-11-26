BIN     := nats-agent
PKG     := github.com/Superm4n97/artifacts/nats-agent
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOOS    ?= $(shell go env GOOS)
GOARCH  ?= $(shell go env GOARCH)
LDFLAGS := -s -w -X $(PKG)/cmd.Version=$(VERSION)

UNIT_PKGS := $(shell go list ./... | grep -v '/e2e$$')

.PHONY: all build test vet unit-test e2e-test clean

all: test build

build:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath \
		-ldflags "$(LDFLAGS)" -o dist/$(BIN)-$(GOOS)-$(GOARCH) .

test: vet unit-test e2e-test

vet:
	go vet ./...

unit-test:
	go test -race -count=1 $(UNIT_PKGS)

e2e-test:
	go test -race -count=1 ./e2e/

clean:
	rm -rf dist
