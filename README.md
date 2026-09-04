# delegateed

> **⚠️ IMPORTANT DISCLAIMER: ALPHA SOFTWARE**
> `delegateed` is currently in alpha stage. This software is experimental and under active development.
> Use at your own risk.

## What is delegateed?

`delegateed` is a renewal service for Arkade. A user locks coins in a
**delegate VTXO** and goes offline; `delegateed` refreshes those coins through
a batch before they expire, for as long as the delegation stays registered.
The user's key is never needed, and the service can never redirect the funds:
the emulator only co-signs a spend that satisfies the delegate covenant.

A delegate VTXO is a taproot output with two leaves:

| leaf | keys | purpose |
|------|------|---------|
| delegate | `arkd signer` + `emulator key tweaked with the covenant` | batch renewal, driven by this service |
| exit | `user` + CSV | unilateral exit, always available |

The covenant only passes for a **batch registration intent** that

- is within `renewal_window` seconds of the VTXO's expiry (chosen by the user at registration, baked into the address),
- has no onchain outputs,
- names exactly one vtxo tree cosigner: this service's `delegate_pubkey`,
- preserves script, value and assets of input *i* on output *i-1* (`OP_TUNNEL`).

Every poll, the service lists the spendable VTXOs of each registered address
from the arkd indexer. All VTXOs inside their window are renewed in one intent:
the service gets it signed by the emulator, registers it with arkd, cosigns the
vtxo tree, and at finalization builds the forfeits and has the emulator and arkd
sign them. The refreshed leaf lands at the same address, so it is picked up
again next cycle.

## Supported Networks

`delegateed` follows the network of the arkd instance it connects to:
regtest, testnet3, testnet4, signet, mutinynet, mainnet.

It requires an [emulator](https://github.com/arkade-os/emulator) ≥ v0.0.8-rc.0
(`OP_PUSHEXPIRY`, `OP_CHECKTIMEVERIFY`, `OP_INSPECTINTENTMESSAGE`, `OP_TUNNEL`)
and a postgres database.

## Usage Documentation

### Installing

Build from source (Go ≥ 1.26):

```sh
make build
./bin/delegateed
```

or use the container image: `ghcr.io/arkade-os/delegatee`.

### Configuration Options

`delegateed` is configured with environment variables.

| Environment variable | Description | Default |
|---|---|---|
| `DELEGATEE_ARK_URL` | arkd gRPC address (`host:port`), also serves the indexer | required |
| `DELEGATEE_EMULATOR_URL` | emulator gRPC address; `https://` prefix enables TLS | required |
| `DELEGATEE_DATABASE_URL` | postgres DSN | required |
| `DELEGATEE_SECRET_KEY` | 32-byte hex; the vtxo tree cosigner key pinned in every delegate address. Changing it changes all addresses. | required |
| `DELEGATEE_PORT` | public gRPC + REST gateway port | `7080` |
| `DELEGATEE_ADMIN_PORT` | admin gRPC + REST gateway port; bind it to a private network | `7081` |
| `DELEGATEE_POLL_INTERVAL` | scan period | `1m` |
| `DELEGATEE_RENEWAL_TIMEOUT` | max time from intent registration to batch finalization; must cover the gap between two arkd sessions | `2h` |
| `DELEGATEE_MAX_VTXOS_PER_INTENT` | inputs per intent proof. The covenant runs 4 `OP_INSPECTINTENTMESSAGE` per input and the emulator allows 64 per request, so 16 is the ceiling; arkd's `MAX_TX_WEIGHT` allows about 80. | `16` |
| `DELEGATEE_LOG_LEVEL` | logrus level (5 = debug) | `4` |

### API

Two gRPC services (see
[service.proto](api-spec/protobuf/delegatee/v1/service.proto)), each with a
JSON gateway on its port. `DelegateeService` is public; `AdminService` has no
authentication and must only be reachable from a private network.

| service | rpc | REST | |
|---------|-----|------|-|
| public | `GetInfo` | `GET /v1/info?renewalWindow=N` | `delegatePubkey`, `serverPubkey`, `emulatorTweakedPubkey`, `delegateTapscript`, `arkadeScript` for a renewal window of N seconds (default 1024) |
| public | `RegisterDelegation` | `POST /v1/delegate` | `{"tapscripts": ["<hex>", ...], "renewalWindow": N}` → delegation. The tapscripts must contain the `delegateTapscript` for that window and an exit leaf. |
| admin | `ListDelegations` | `GET /v1/admin/delegate` | all delegations |
| admin | `GetDelegation` | `GET /v1/admin/delegate/{address}` | delegation, live `vtxos` from the indexer, `renewals` history |
| admin | `CancelDelegation` | `DELETE /v1/admin/delegate/{address}` | stop renewing; register again to resume |
| both | grpc health | `GET /healthz` | NOT_SERVING when postgres, arkd or the emulator is unreachable |

To build an address, a wallet picks a renewal window (or keeps the default),
takes the matching `delegateTapscript` from `GetInfo`, adds its own CSV exit
leaf, encodes the tapscripts and registers them with the same window. See
[test/e2e/delegate_test.go](test/e2e/delegate_test.go) for the Go version.

## Provisioning

- **Key**: `DELEGATEE_SECRET_KEY` is the identity of the service. Every delegate
  address pins its pubkey; losing or rotating it strands funds in addresses the
  service will skip (they keep their unilateral exit). Back it up.
- **Startup**: the binary retries arkd and the emulator for ~2.5 min, then exits;
  run it under a restart policy.
- **Shutdown** waits for the in-flight batch (bounded by `RENEWAL_TIMEOUT`):
  an intent abandoned mid-round makes arkd fail rounds until it drops it.
  Give the process a matching termination grace period.
- **Failures** are recorded per attempt in `renewals` (visible in
  `GetDelegation`) and retried on the next poll.
- **Throughput**: each cycle queries the indexer in batches of 100 scripts,
  splits expiring VTXOs into intents of `MAX_VTXOS_PER_INTENT`, registers all
  of them and drives one batch session per round until every intent has been
  included, with a single tree signer per round. arkd's
  `ROUND_MAX_PARTICIPANTS_COUNT` bounds how many intents fit in one round. An
  intent the emulator rejects is retried one VTXO per intent within the same
  cycle, so a bad VTXO only ever blocks itself.
- **Timing**: keep `POLL_INTERVAL` well under the smallest renewal window users
  pick, and `RENEWAL_TIMEOUT` above the arkd session period.
- **Fees**: the covenant forces `sum(outputs) == sum(inputs)`, so arkd's intent
  fee must be zero for delegate VTXOs.
- **Exposure**: the public API only registers covenant scripts, which cannot
  move funds; rate-limit it behind a reverse proxy. The admin API can cancel
  renewals for any address: never expose `ADMIN_PORT` publicly.
- **Scale**: one instance per key. In-flight renewals are tracked in memory.

## Repository Structure

- [`api-spec`](./api-spec/): protobuf definitions, generated stubs and OpenAPI spec
- [`cmd/delegateed`](./cmd/delegateed/): entrypoint
- [`internal/config`](./internal/config/): environment config and service wiring
- [`internal/core/application`](./internal/core/application/): covenant, scanner and renewal flow
- [`internal/core/domain`](./internal/core/domain/): delegation model and repository interface
- [`internal/infrastructure/db/postgres`](./internal/infrastructure/db/postgres/): sqlc queries and migrations
- [`internal/interface/grpc`](./internal/interface/grpc/): gRPC server, JSON gateway, handlers
- [`test/e2e`](./test/e2e/): end-to-end tests against a regtest stack

## Development

### Compile binary from source

```sh
make build
```

### Local Development Setup

Everything needed for regtest is in [docker-compose.regtest.yml](docker-compose.regtest.yml):
bitcoin and the explorer come from [nigiri](https://github.com/vulpemventures/nigiri),
the rest (nbxplorer, arkd-wallet, arkd v0.9.13, emulator v0.0.8-rc.0, postgres)
from the compose file. `make regtest-up` also runs
[scripts/regtest-init.sh](scripts/regtest-init.sh), which creates, unlocks and
funds the arkd wallet through its admin API (port 7071).

```sh
make regtest-up     # nigiri + arkd + emulator + postgres
make run            # delegateed from source on :7080 / admin :7081
make regtest-down
```

`make regtest-run` starts the same stack with `delegateed` in docker instead.
The arkd and emulator services are the same as in the emulator repo and use
the same container names and ports, so stop one stack before starting the
other. `EMULATOR_VERSION` overrides the emulator image tag.

### Testing

```sh
make test       # unit tests
make test-e2e   # regtest stack must be up; recreates postgres, then runs real renewals
```

The e2e suite funds a wallet through the faucet and covers: two consecutive
renewals of one VTXO (offchain tx → batch leaf → batch leaf), an asset VTXO,
ten delegations renewed in one batch, forty-eight delegations spread over three
intents of one batch, and several renewal windows including one too far from
expiry to be touched.

### Protobuf and SQL generation

```sh
make proto                 # regenerate stubs and OpenAPI spec with buf
make pgsqlc                # regenerate sqlc queries
make FILE=name pgmigrate   # create a new migration pair
```
