GOBIN ?= $(shell go env GOPATH)/bin
FUZZTIME ?= 10s

.PHONY: all
all: fmt vet test

.PHONY: fmt
fmt:
	@gofmt -l .
	@test -z "$$(gofmt -l .)" || { echo "run: gofmt -w ."; exit 1; }

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test -count=1 ./...

.PHONY: race
race:
	go test -race -count=1 ./...

.PHONY: cover
cover:
	go test -count=1 -covermode=atomic -coverpkg=./... -coverprofile=cover.out ./...
	go tool cover -func=cover.out | tail -1

# The gate lives in .testcoverage.yml. go-test-coverage is installed on demand and never
# added to go.mod: the library's zero-dependency promise covers its own module file.
.PHONY: check-coverage
check-coverage: $(GOBIN)/go-test-coverage cover
	$(GOBIN)/go-test-coverage --config=./.testcoverage.yml

$(GOBIN)/go-test-coverage:
	go install github.com/vladopajic/go-test-coverage/v2@latest

.PHONY: fuzz
fuzz:
	go test -run '^$$' -fuzz FuzzParseBindingResponse -fuzztime=$(FUZZTIME) .
	go test -run '^$$' -fuzz FuzzParseXORMappedAddress -fuzztime=$(FUZZTIME) .
	go test -run '^$$' -fuzz FuzzParseMappedAddress -fuzztime=$(FUZZTIME) .
	go test -run '^$$' -fuzz FuzzParseAddressBody -fuzztime=$(FUZZTIME) .

# Discovery against the real services. Needs network egress and, to exercise the IPv6
# paths, a host with a routable IPv6 address; it is deliberately outside the unit suite.
.PHONY: integration
integration:
	go test -tags integration -count=1 -v -timeout 5m ./...

.PHONY: build
build:
	go build -o publicip ./cmd/publicip

.PHONY: cross
cross:
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			out="publicip-$$os-$$arch"; \
			[ "$$os" = windows ] && out="$$out.exe"; \
			GOOS=$$os GOARCH=$$arch go build -o "/tmp/$$out" ./cmd/publicip || exit 1; \
			echo "  built $$out"; \
		done; \
	done

.PHONY: clean
clean:
	rm -f cover.out publicip publicip-*
