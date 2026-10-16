.PHONY: build test vet run clean

build:
	go build -o featherd .

test:
	go test ./...

vet:
	go vet ./...

# FEATHERD_AUTH has no default here either: make run FEATHERD_AUTH=none
run: build
	./featherd --addr 127.0.0.1:8333 --dir data

clean:
	rm -f featherd
