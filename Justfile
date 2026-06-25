# Copyright (c) 2026 bata94
# SPDX-License-Identifier: MIT WITH Commons-Clause

list:
	@just --list

build:
	go build -ldflags="-s -w -X main.Version=$(cat VERSION 2>/dev/null || echo dev)" -o northstar .

run:
	go run .

test:
	go test -v ./...

test-fast:
	go test -count=1 -race -shuffle=on ./...

test-cover:
	go test -coverprofile=coverage.out -covermode=atomic ./...

test-all:
	go test -count=1 -race -shuffle=on -tags=integration -coverprofile=coverage.out -covermode=atomic ./...

test-blast:
	go test -v -run 'TestBlast|Benchmark' -timeout=5m ./resolver/

bench:
	go test -bench=. -benchmem -benchtime=1x ./resolver/

fmt:
	go fmt ./...

lint:
	golangci-lint run

clean:
	rm -rf ./northstar
	rm -rf ./*.log

check:
  just fmt
  just lint
  just test
  just build

  just test-fast
  just test-cover
  just test-all
  just test-blast
  just bench

alias dc := run-docker
run-docker:
  docker compose down && docker compose up -d --build northstar && docker compose up -d && docker compose logs -f

alias dc-dev := run-docker-dev
run-docker-dev:
  docker compose down && docker compose up -d northstar-dev && docker compose logs -f

release-patch:
  just check
  ./scripts/release.sh patch

release-minor:
  just check
  ./scripts/release.sh minor

release-major:
  just check
  ./scripts/release.sh major
