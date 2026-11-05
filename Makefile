VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BINARY = delegateed
LDFLAGS := -s -w -X 'main.Version=$(VERSION)'

.PHONY: build build-all clean test test-daemon test-e2e lint lint-fix fmt deps docker regtest-up regtest-run regtest-down run proto proto-lint pg sqlc migration

build:
	go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/delegateed

## build-all: release binaries for every platform
build-all:
	@for os in linux darwin; do for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags="$(LDFLAGS)" -o build/$(BINARY)-$$os-$$arch ./cmd/delegateed; \
	done; done

clean:
	rm -rf bin/ build/

## unit and repository tests (postgres tests need `make pg`)
test:
	go test -race ./internal/... ./cmd/...
	cd pkg/template && go test -race ./...

## the in-process daemon suite against postgres
test-daemon: pg
	go test -count=1 -timeout 15m ./test/daemon/...

## end-to-end against the regtest stack (make regtest-up first)
test-e2e:
	go test -tags e2e -v -count=1 -timeout 40m ./test/e2e/...

pg:
	docker compose -f docker-compose.regtest.yml up -d --wait pg

lint:
	golangci-lint run ./...
	cd pkg/template && golangci-lint run ./...

lint-fix:
	golangci-lint run --fix ./...
	cd pkg/template && golangci-lint run --fix ./...

## proto: regenerates api-spec/protobuf/gen and the openapi spec with buf (docker)
proto: proto-lint
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

proto-lint:
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf lint

fmt:
	gofmt -s -w .

## sqlc: compile sql queries for postgres
sqlc:
	@docker run --rm -v ./internal/infrastructure/postgres:/src -w /src sqlc/sqlc:1.30.0 generate

## migration: create a postgres migration file (e.g. make FILE=add_x migration)
migration:
	@docker run --rm -v ./internal/infrastructure/postgres/migration:/migration migrate/migrate create -ext sql -dir /migration $(FILE)

deps:
	go mod tidy

docker:
	docker build -t ghcr.io/arkade-os/delegatee:$(VERSION) .

# nigiri can believe it is running after a docker restart: trust the container
NIGIRI_UP = docker ps --format '{{.Names}}' | grep -qx bitcoin || { nigiri stop >/dev/null 2>&1; nigiri start; }

## regtest-up: nigiri + arkd + emulator + fulcrum + postgres (delegateed runs from `make run` or the tests)
regtest-up:
	@$(NIGIRI_UP)
	docker compose -f docker-compose.regtest.yml up -d
	./scripts/regtest-init.sh

## regtest-run: the same stack plus delegateed in docker (ports 7080 / 7081)
regtest-run:
	@$(NIGIRI_UP)
	docker compose -f docker-compose.regtest.yml --profile delegatee up -d --build
	./scripts/regtest-init.sh

regtest-down:
	docker compose -f docker-compose.regtest.yml --profile delegatee down -v
	nigiri stop --delete

## run: delegateed from source against the regtest stack
run: build
	DELEGATEE_DATABASE_URL=postgres://postgres@localhost:5432/delegatee?sslmode=disable \
	DELEGATEE_LOG_LEVEL=5 ./bin/$(BINARY)
