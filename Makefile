GO ?= go

.PHONY: test check fmt vet standalone

test:
	$(GO) test ./...

check: fmt vet test standalone

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

# Proves the module builds without the Go workspace, which is what a consumer
# and CI actually see. A workspace silently satisfies a missing require, so a
# build that works on a laptop can fail everywhere else with no local symptom.
standalone:
	GOWORK=off GOFLAGS=-mod=readonly $(GO) build ./...
	@echo "checking that only dnsx/publicres reaches for a DNS library"
	@GOWORK=off $(GO) mod why github.com/miekg/dns | grep -q 'mailkit/dnsx/publicres' \
		|| (echo "miekg/dns is reachable from somewhere it should not be"; exit 1)
