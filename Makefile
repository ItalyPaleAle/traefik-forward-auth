.PHONY: test
test:
	go test -tags unit ./...

.PHONY: test-race
test-race:
	CGO_ENABLED=1 go test -race -tags unit ./...

.PHONY: lint
lint:
	golangci-lint run -c .golangci.yaml

.PHONY: build-client
build-client:
	cd client && sh build.sh

.PHONY: gen-config
gen-config:
	go run ./tools/gen-config

# Ensure gen-config ran
.PHONY: check-config-diff
check-config-diff: gen-config
	git diff --exit-code config.sample.yaml README.md docs/03-all-configuration-options.md
