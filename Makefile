VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BINARY = delegateed
LDFLAGS := -s -w -X 'main.Version=$(VERSION)'

.PHONY: build build-all clean test test-e2e lint fmt deps docker regtest-up regtest-run regtest-down run proto proto-lint pgsqlc pgmigrate

build:
	go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/delegateed

## build-all: release binaries for every platform
build-all:
	@for os in linux darwin; do for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags="$(LDFLAGS)" -o build/$(BINARY)-$$os-$$arch ./cmd/delegateed; \
	done; done

clean:
	rm -rf bin/ build/

## unit tests (no infrastructure), with coverage per package
test:
	go test -short -race -cover ./...

## repository tests against postgres, then end-to-end against the regtest stack (make regtest-up first)
test-e2e:
	docker compose -f docker-compose.regtest.yml up -d --force-recreate --wait pg
	go test -v -count=1 -timeout 25m ./internal/infrastructure/... ./test/e2e/...

lint:
	golangci-lint run ./...

## proto: regenerates api-spec/protobuf/gen and the openapi spec with buf (docker)
proto: proto-lint
	@echo "Compiling stubs..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

proto-lint:
	@echo "Linting protos..."
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf lint

fmt:
	gofmt -s -w .

## pgsqlc: compile sql queries for postgres
pgsqlc:
	@docker run --rm -v ./internal/infrastructure/db/postgres:/src -w /src sqlc/sqlc:1.30.0 generate

## pgmigrate: create a postgres migration file (e.g. make FILE=add_x pgmigrate)
pgmigrate:
	@docker run --rm -v ./internal/infrastructure/db/postgres/migration:/migration migrate/migrate create -ext sql -dir /migration $(FILE)

deps:
	go mod tidy

docker:
	docker build -t ghcr.io/arkade-os/delegatee:$(VERSION) .

# nigiri can believe it is running after a docker restart: trust the container
NIGIRI_UP = docker ps --format '{{.Names}}' | grep -qx bitcoin || { nigiri stop >/dev/null 2>&1; nigiri start; }

## regtest-up: nigiri + arkd + emulator + postgres (delegateed runs from `make run` or the tests)
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
	DELEGATEE_ARK_URL=localhost:7070 DELEGATEE_EMULATOR_URL=localhost:7073 \
	DELEGATEE_DATABASE_URL=postgres://postgres@localhost:5432/delegatee?sslmode=disable \
	DELEGATEE_SECRET_KEY=$${DELEGATEE_SECRET_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef} \
	DELEGATEE_LOG_LEVEL=5 DELEGATEE_POLL_INTERVAL=10s ./bin/$(BINARY)
