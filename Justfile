list:
	@just --list

build:
	go build -o northstar .

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

check:
  just fmt
  just lint
  just test
  just build
  just clean
