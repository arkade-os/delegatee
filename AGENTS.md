# Working on delegateed

Read this before changing anything. `docs/handoff.md` has the full state of
the project, what was decided and why, and what is left; `README.md` is the
user guide; `docs/protocol.md` the covenant and renewal flow.

## Invariants: never break these

- **Never change the script existing params produce.** `buildArkadeScript`
  in `internal/core/application/covenant.go` is pinned byte for byte by
  `covenant_test.go` (`goldenNoFeeScript`, `goldenMaxFeeScript`). A changed
  script moves every registered address and strands its coins. New behaviour
  means a new script variant, never an edit of an existing one.
- **No forfeit without `validateBatch`.** `OnBatchFinalization` in
  `renewal.go` must keep checking the vtxo tree, one leaf per renewed coin
  and the connector root before anything is signed. This is what stops a
  dishonest arkd from taking the coins.
- **A fee-paying delegation is never renewed in the first half of a vtxo's
  life** (`dueAt`). Without it the service pays arkd in every round.
- **Proof input i is paid by output i-1.** Every part of the intent
  (outputs, asset packet, emulator entries, forfeits, `leavesPay`) assumes it.
- **Admin port = public API + admin API + UI + metrics, no CORS.** The public
  port has CORS and the rate limit, and nothing else.

## Layout

arkd-style: `api-spec/protobuf/delegatee/v1/service.proto` (buf, meshapi
gateway on the same port as grpc), `internal/interface/grpc` (server,
handlers, embedded UI in `web/index.html`, metrics, rate limit),
`internal/core/application` (covenant, scan, renewal, revocation),
`internal/core/domain`, `internal/infrastructure/db/postgres` (sqlc +
migrations), `test/e2e` (regtest). Interfaces with a single implementation
(`application.Service`, `DelegationRepository`) are house style: keep them.

## Commands

```sh
make test          # unit, offline, -race, coverage
make regtest-up    # nigiri + arkd + emulator + postgres (docker)
make test-e2e      # repository tests + e2e, ~8 min, needs regtest-up
make proto         # buf via docker, after editing the proto
make pgsqlc        # sqlc, after editing query.sql; keep the "sqlc v1.27.0" header
make lint          # golangci-lint
```

Verify before claiming done: `gofmt -s -l .` empty, `go vet ./...`,
`golangci-lint run ./...`, `make test`, and `make test-e2e` for anything that
touches renewals, the covenant, forfeits or the API.

## Gotchas

- `make regtest-up` self-heals a stale nigiri, but the emulator image must be
  ≥ v0.0.8-rc.0 (OP_PUSHEXPIRY, OP_INSPECTINTENTMESSAGE, OP_TUNNEL).
- `TestIntentFees` takes ~4.5 min: it waits for the half-life rule on regtest.
- `TestScale` is sized by build tag (`scale_size*_test.go`): the race
  detector makes curve math ~15x slower.
- The fake indexer (`fakes_test.go`) cannot see which scripts are asked for:
  it serves its vtxos to the first request of a scan only (`serve(...)`).
- The gateway calls grpc over loopback on the same port: with an admin
  password, that call carries its own credentials (`loopbackAuth`).
- arkd's indexer returns unpaged requests in full today; `spendableVtxos`
  follows pages anyway. Don't remove that.
- The policy/plugin abstraction was removed on purpose: a user-supplied
  template system is planned and will replace the hardwired covenant. See
  the `TODO(templates)` in `covenant.go`; don't rebuild a registry.

## Commits

Commits are authored and GPG-signed by the repository owner only: no
`Co-Authored-By` trailers, no tool attribution. Never push.
