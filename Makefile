.PHONY: test
test:
	go test -tags unit ./...

.PHONY: test-race
test-race:
	CGO_ENABLED=1 go test -race -tags unit ./...

.PHONY: lint
lint:
	golangci-lint run -c .golangci.yaml

.PHONY: gen-config
gen-config:
	go run ./tools/gen-config

# Ensure gen-config ran
.PHONY: check-config-diff
check-config-diff: gen-config
	git diff --exit-code config.sample.yaml README.md docs/03-all-configuration-options.md

.PHONY: clean
clean:
	rm -rf client/dist
	rm -rf .bin

client/node_modules:
	cd client && npm install

client/dist: client/node_modules
	cd client && ./build.sh

.PHONY: resources
resources: client/node_modules client/dist

.PHONY: .bin/linux-amd64/traefik-forward-auth
.bin/linux-amd64/traefik-forward-auth: resources
	echo -e "\n###\nBuilding for amd64\n"
	mkdir -p .bin/linux-amd64
	CGO_ENABLED=0 \
	GOOS=linux \
	GOARCH=amd64 \
	go build \
	-o .bin/linux-amd64/traefik-forward-auth \
	-trimpath \
	./cmd/traefik-forward-auth

.PHONY: .bin/linux-arm/traefik-forward-auth
.bin/linux-arm/traefik-forward-auth: resources
	echo -e "\n###\nBuilding for armhf\n"
	mkdir -p .bin/linux-arm
	CGO_ENABLED=0 \
	GOOS=linux \
	GOARCH=arm \
	go build \
	-o .bin/linux-arm/traefik-forward-auth \
	-trimpath \
	./cmd/traefik-forward-auth

.PHONY: .bin/linux-arm64/traefik-forward-auth
.bin/linux-arm64/traefik-forward-auth: resources
	echo -e "\n###\nBuilding for arm64\n"
	mkdir -p .bin/linux-arm64
	CGO_ENABLED=0 \
	GOOS=linux \
	GOARCH=arm64 \
	go build \
	-o .bin/linux-arm64/traefik-forward-auth \
	-trimpath \
	./cmd/traefik-forward-auth

.PHONY: build
build: .bin/linux-amd64/traefik-forward-auth .bin/linux-arm64/traefik-forward-auth .bin/linux-arm/traefik-forward-auth

