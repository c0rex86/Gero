.PHONY: build clean install test run

VERSION := 1.0.0
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X github.com/c0rex86/gero/cmd.Version=$(VERSION) -X github.com/c0rex86/gero/cmd.GitCommit=$(COMMIT) -X github.com/c0rex86/gero/cmd.BuildTime=$(BUILD_TIME)"

build:
	go build $(LDFLAGS) -o gero

install: build
	cp gero /usr/local/bin/

clean:
	rm -f gero

test:
	go test ./...

run: build
	./gero

server: build
	./gero server

client: build
	./gero client

all: clean build test 