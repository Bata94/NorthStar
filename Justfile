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

alias dc := run-docker
run-docker:
  docker compose down && docker compose up -d --build northstar && docker compose up -d && docker compose logs -f

release-patch:
  just check
	./scripts/release.sh patch

release-minor:
  just check
	./scripts/release.sh minor

release-major:
  just check
	./scripts/release.sh major
