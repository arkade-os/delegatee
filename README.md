# delegateed

> **⚠️ IMPORTANT DISCLAIMER: ALPHA SOFTWARE**
> `delegateed` is currently in alpha stage. This software is experimental and under active development.
> Use at your own risk.

## What is delegateed?

`delegateed` keeps Arkade coins alive while their owner is offline. A user
locks coins in a **delegate VTXO**; `delegateed` refreshes them through an
arkd batch shortly before they expire, again and again, for as long as the
delegation stays registered.

- The user's key is never needed.
- The service cannot move the funds anywhere else: every spend is co-signed by
  the [emulator](https://github.com/arkade-os/emulator), and only if it
  satisfies the covenant the user chose. The refreshed coin lands at the same
  address.
- The user can always leave with their own key (unilateral exit leaf).

How the covenant works, byte by byte, is in [docs/protocol.md](docs/protocol.md).

## Quick start

You need an arkd, an emulator v0.0.8-rc.1 connected to it, and a postgres
database.

```sh
docker run -d --restart unless-stopped \
  -p 7080:7080 -p 127.0.0.1:7081:7081 \
  -e DELEGATEE_ARK_URL=arkd.example.com:7070 \
  -e DELEGATEE_EMULATOR_URL=https://emulator.example.com \
  -e DELEGATEE_DATABASE_URL=postgres://user:pass@db:5432/delegatee \
  -e DELEGATEE_SECRET_KEY=$(openssl rand -hex 32) \
  -v "$PWD/admin-users:/run/secrets/admin-users:ro" \
  -e DELEGATEE_ADMIN_AUTH=file \
  -e DELEGATEE_ADMIN_USERS_FILE=/run/secrets/admin-users \
  ghcr.io/arkade-os/delegatee
```

Create `admin-users` with one bcrypt record per operator, for example
`htpasswd -B -C 12 -bn alice 'choose-a-password' > admin-users`. Keep the secret key
(or keyring) mounted as a secret: keys are pinned in delegate addresses (see
[Running in production](#running-in-production)). Then:

- wallets talk to `http://host:7080` (gRPC and REST on the same port),
- you open `http://localhost:7081/` for the operator UI.

To try everything locally on regtest instead, see [Development](#development).

## Delegating coins (wallet integration)

All calls below are REST; the same RPCs exist over gRPC
([service.proto](api-spec/protobuf/delegatee/v1/service.proto),
[OpenAPI](api-spec/openapi/swagger/delegatee/v1/service.openapi.json)).

**1. Choose the params.** They are baked into the address and cannot be
changed later; to change them, move the coins to a new delegate address.

| param | meaning | default |
|---|---|---|
| `renewalWindow` | seconds before expiry from which the coin may be renewed. Larger is safer against downtime, smaller renews (and pays fees) less often. Keep it well above the arkd session interval. | `1024` |
| `maxFee` | most sats one renewal may take from the coin to pay arkd's intent fee, see [Fees](#fees) | `0` |

**2. Get the delegate leaf** for those params:

```sh
curl 'http://localhost:7080/v1/info?renewalWindow=86400&maxFee=200'
```

```json
{
  "network": "regtest",
  "delegatePubkey": "03…",
  "serverPubkey": "02…",
  "emulatorTweakedPubkey": "02…",
  "arkadeScript": "db…",
  "delegateTapscript": "20…ac",
  "renewalWindow": "86400", "maxFee": "200"
}
```

A careful wallet rebuilds `arkadeScript` itself ([docs/protocol.md](docs/protocol.md))
instead of trusting the response: that script is the whole security model.

**3. Build the VTXO script**: `delegateTapscript` plus the leaves of a
normal Arkade VTXO, your forfeit leaf (`<user key> <server key>`, so you can
still spend the coin cooperatively) and your exit leaf (`<user key>` behind
a CSV). Registration requires the delegate leaf and an exit leaf and accepts
any other. Encode the tapscripts the way the SDKs do.

**4. Register it** with the same params:

```sh
curl -X POST http://localhost:7080/v1/delegate -H 'Content-Type: application/json' -d '{
  "tapscripts": ["20…ac", "03…ac"], "renewalWindow": 86400, "maxFee": 200 }'
```

The response carries the Ark `address`. Registration fails with
`INVALID_ARGUMENT` if the tapscripts don't contain the delegate leaf for these
exact params, or lack an exit leaf.

**5. Send coins to the address.** Any number of VTXOs, with or without assets.

**6. Check on it** whenever you like:

```sh
curl http://localhost:7080/v1/delegate/<address>
```

returns the delegation, its live `vtxos` and the `renewals` of the last 30
days, each with the batch `commitmentTxid` or the `error` that prevented it.

**7. Stop delegating** whenever you like, with a signature from the exit key:

```sh
curl -X POST http://localhost:7080/v1/delegate/<address>/revoke -H 'Content-Type: application/json' -d '{
  "pubkey": "<exit key, hex>", "signature": "<hex>", "timestamp": 1758100000 }'
```

`signature` is a BIP340 signature by a key of your exit leaf over
`tagged_hash("delegatee/revoke", "<address>:<timestamp>")`; `timestamp` is
unix seconds and must be within ten minutes of the server's clock, so a
captured signature cannot be replayed later. The delegation shows as
`revoked` (as opposed to `cancelled` by the operator). Register again to resume.

A complete Go example is in [test/e2e/delegate_test.go](test/e2e/delegate_test.go)
and the REST flow in [test/e2e/scenarios_test.go](test/e2e/scenarios_test.go).

### Fees

arkd operators can charge a fee per intent input and output. A renewal has no
one to bill but the coin itself, so the user decides up front how much a
renewal may cost: `maxFee`.

- Each cycle the service reads arkd's current fee programs, prices every coin
  and renews it for `amount − fee`.
- If the fee is above `maxFee`, the coin is **not renewed**. The attempt is
  recorded (`intent fee 120 exceeds the delegation max fee 100`) and retried
  every poll, so it goes through as soon as arkd's fee drops.
- With `maxFee: 0` the covenant requires the exact same amount back: the coin
  is only renewed while arkd charges nothing for it.
- The covenant cannot tell arkd's real fee from an inflated one, so treat
  `maxFee` as what a misbehaving operator could take **each time the coin is
  renewable**. Pick it accordingly: a few times arkd's current fee leaves
  room for fee changes without exposing much.
- **Keep `renewalWindow` well below the VTXO lifetime (arkd's batch expiry)
  when `maxFee` > 0.** A coin is renewable whenever it is inside its window;
  if the window covers the whole lifetime it is renewable in every round, and
  `maxFee` could be taken every round instead of once per lifetime. A window
  of 10–25% of the lifetime is a sane range. `delegateed` itself never renews
  a fee-paying delegation in the first half of a VTXO's life, whatever the
  window, but the covenant cannot enforce that on a dishonest operator.

### API summary

| port | rpc | REST | |
|---|---|---|---|
| public | `GetInfo` | `GET /v1/info?renewalWindow=&maxFee=` | keys, covenant and delegate tapscript for the params |
| public | `RegisterDelegation` | `POST /v1/delegate` | start renewing an address; also resumes a stopped one |
| public | `GetDelegation` | `GET /v1/delegate/{address}` | delegation, live VTXOs, renewal history |
| public | `RevokeDelegation` | `POST /v1/delegate/{address}/revoke` | stop renewing, signed by the owner's exit key |
| admin | `ListDelegations` | `GET /v1/admin/delegate` | every delegation with its last renewal, amount watched, next expiry |
| admin | `GetStatus` | `GET /v1/admin/status` | last scan, renewal in flight, arkd's fee programs |
| admin | `CancelDelegation` | `DELETE /v1/admin/delegate/{address}` | stop renewing |
| admin | — | `GET /metrics` | Prometheus metrics, see [Monitoring](#monitoring) |
| both | grpc health | `GET /healthz` | `NOT_SERVING` when postgres, arkd or the emulator is unreachable, or the scanner stopped |

The admin port also serves the whole public API and the operator UI.

## Monitoring

`GET /metrics` on the admin port (basic auth applies, Prometheus supports it):

| metric | meaning |
|---|---|
| `delegatee_vtxos_late`, `delegatee_sats_late` | coins renewable for a while and still not renewed (in the last quarter of their renewable time). **Alert when > 0**: arkd rounds are stalled, the emulator refuses, or fees exceed what owners allowed. |
| `delegatee_last_scan_timestamp_seconds` | alert when older than a few `POLL_INTERVAL`s while `delegatee_vtxos_renewing` is 0 |
| `delegatee_dependency_up{name}` | `database`, `ark`, `emulator`, `scanner`; the same checks as `/healthz` |
| `delegatee_renewals_total{result}` | `ok` / `failed` vtxo renewals since start |
| `delegatee_delegations_active`, `delegatee_delegations_foreign` | foreign = registered under another key: alert if it ever rises after a deploy, the key changed |
| `delegatee_vtxos_watched`, `delegatee_sats_watched`, `delegatee_vtxos_renewing` | what is under management right now |

Suggested rules:

```yaml
- alert: DelegateeCoinsLate
  expr: delegatee_vtxos_late > 0
  for: 5m
- alert: DelegateeScannerStalled
  expr: time() - delegatee_last_scan_timestamp_seconds > 600 and delegatee_vtxos_renewing == 0
- alert: DelegateeDependencyDown
  expr: delegatee_dependency_up == 0
  for: 2m
```

`/healthz` also turns `NOT_SERVING` when no scan completed for three poll
intervals (a minute at least) outside a batch, so a wedged loop is caught by
plain liveness probes too. Every late coin is logged once per scan.

## Operator UI

`http://<admin host>:7081/` — a single page embedded in the binary, no build
step, no external assets.

- **Needs attention** opens first when any active delegation failed its last
  renewal, with the reason in the list.
- The status line says when the last scan ran, whether a batch is being
  renewed right now, how much is being watched and whether arkd charges fees.
- The overview puts every address on one time axis (next expiry, renewable
  from when) and shows arkd's current fee programs.
- Each VTXO shows a lifetime bar: time elapsed, the renewable part at the end,
  and where "now" is.
- Flags delegations that failed, that are renewable for long without being
  renewed (stalled arkd rounds), or that were registered under another key.
- <kbd>↑</kbd> <kbd>↓</kbd> move through the list, <kbd>/</kbd> searches,
  <kbd>Esc</kbd> returns to the overview. Follows the system light/dark theme.
- **Stop renewing** / **Resume renewing** per address, search by address,
  refresh every 15 s, health of arkd / emulator / postgres in the header.

Set `DELEGATEE_ADMIN_USERS_FILE` to a file containing `username:bcrypt-hash`
records. The browser asks for the operator's username and password, and gRPC
clients send the same HTTP Basic credentials. Passwords are checked against
the hashes and failed attempts are rate-limited. Set
`DELEGATEE_ADMIN_AUTH=disabled` when a trusted reverse proxy or network policy
owns authentication instead. Basic auth still needs TLS:
keep the port on localhost or a private network, or put a TLS reverse proxy in
front of it. `LoadConfig` requires either `ADMIN_AUTH=file` with a users file,
or the explicit `ADMIN_AUTH=disabled` setting.

## Configuration

Environment variables only.

| Environment variable | Description | Default |
|---|---|---|
| `DELEGATEE_ARK_URL` | arkd gRPC address (`host:port`), also serves the indexer | required |
| `DELEGATEE_EMULATOR_URL` | emulator gRPC address; `https://` prefix enables TLS | required |
| `DELEGATEE_DATABASE_URL` | postgres DSN; migrations run at startup | required |
| `DELEGATEE_SECRET_KEY` | 32-byte hex; the vtxo tree cosigner key pinned in every delegate address | required, or the file |
| `DELEGATEE_SECRET_KEY_FILE` | file holding that hex (docker / kubernetes secrets); wins over the variable | unset |
| `DELEGATEE_SECRET_KEYS_FILE` | newline-separated keyring; first key is active for new addresses, remaining keys renew older addresses | unset |
| `DELEGATEE_PREVIOUS_SECRET_KEYS` | comma-separated previous 32-byte hex keys, for rotation when using `SECRET_KEY` or `SECRET_KEY_FILE` | unset |
| `DELEGATEE_PUBLIC_RATE_LIMIT` | requests per second per client IP on the public port, burst 10×; `0` disables. Applies to the connection's address: disable it and use the proxy's limits when one terminates connections | `5` |
| `DELEGATEE_PORT` | public gRPC + REST port | `7080` |
| `DELEGATEE_ADMIN_PORT` | admin gRPC + REST + UI port | `7081` |
| `DELEGATEE_POLL_INTERVAL` | how often addresses are scanned | `1m` |
| `DELEGATEE_COLLECTION_WINDOW` | maximum deliberate wait from renewal eligibility to collect more VTXOs; urgent or full intents submit sooner; `0s` disables | `30s` |
| `DELEGATEE_RENEWAL_TIMEOUT` | max time from intent registration to batch finalization; must cover the gap between two arkd sessions | `2h` |
| `DELEGATEE_ADMIN_AUTH` | `file` enables per-operator auth; `disabled` delegates auth to a trusted proxy/network boundary | required |
| `DELEGATEE_ADMIN_USERS_FILE` | newline-separated `username:bcrypt-hash` records when admin auth is `file` | required with `file` |
| `DELEGATEE_MAX_DELEGATIONS` | cap on active delegations; registrations beyond it get `RESOURCE_EXHAUSTED` | `50000` |
| `DELEGATEE_MAX_VTXOS_PER_INTENT` | inputs per intent. The emulator allows 64 `OP_INSPECTINTENTMESSAGE` per request and the covenant runs 4 per input, so 16 is the ceiling | `16` |
| `DELEGATEE_LOG_LEVEL` | logrus level (5 = debug) | `4` |

Supported networks are those of the arkd it connects to: regtest, testnet3,
testnet4, signet, mutinynet, mainnet.

## Running in production

- **Back up the secret keyring.** Put the new key first and retain the old key
  below it during rotation. New addresses use the first key; existing
  addresses continue renewing with any retained key. Remove an old key only
  after its addresses have been migrated or deliberately retired. In-flight
  renewals live in memory.
- **Restart policy.** At startup the binary retries arkd and the emulator for
  ~2.5 min, then exits.
- **Termination grace period ≥ `RENEWAL_TIMEOUT`.** Shutdown waits for the
  in-flight batch, because an intent abandoned mid-round makes arkd fail
  rounds until it drops it.
- **Timing.** `POLL_INTERVAL` well under the smallest renewal window your
  users pick; `RENEWAL_TIMEOUT` above the arkd session period.
- **Exposure.** The public API only registers covenant scripts, which cannot
  move funds. It is rate-limited per client IP (`PUBLIC_RATE_LIMIT`), which
  only helps when clients connect directly: behind a reverse proxy, limit
  there. Never expose the admin port directly; use the bcrypt-backed operator
  file and TLS.
- **Flooding.** Every active delegation costs an indexer lookup per poll, so
  junk registrations slow down real renewals. `MAX_DELEGATIONS` bounds that;
  when the cap is hit, look for addresses that never held a VTXO.
- **Monitoring.** See [Monitoring](#monitoring): alert on `delegatee_vtxos_late`
  and use `/healthz` for liveness. A failure is logged and stored once per
  distinct error, not once per poll; history is kept 30 days, plus the latest
  attempt of each delegation.
- **Fees.** If you also run the arkd, remember that raising intent fees above
  users' `maxFee` stops their renewals.
- **Scale.** Built for thousands of delegations on one instance:
  - a scan costs one database read plus one indexer request per 100
    addresses, four at a time. What is derived from a delegation (covenant,
    tweaked key, merkle proof) is computed once and kept: a scan over 5,000
    addresses takes about a millisecond of CPU, 1.4 s before that cache;
  - `DELEGATEE_COLLECTION_WINDOW` (default `30s`, `0s` disables) collects
    eligible VTXOs until the oldest eligibility time plus that window. New
    arrivals and restarts do not extend the deadline. Submission starts sooner
    when one cosigner has `MAX_VTXOS_PER_INTENT` inputs, or waiting would leave
    less than half a VTXO's effective renewal window or two minutes before
    expiry. The scheduler wakes at the deadline even if `POLL_INTERVAL` is
    longer, refreshes the eligible inputs, and prioritizes earliest expiries.
    Scans and arkd round completion can still add latency; this bounds the
    deliberate collection delay, not the time to confirmation;
  - due VTXOs go in intents of `MAX_VTXOS_PER_INTENT`, built and finalized
    four at a time, with one previous-transaction lookup per intent. All
    intents are registered up front and batch sessions are followed until
    every one is included; arkd's `ROUND_MAX_PARTICIPANTS_COUNT` bounds how
    many fit in one round, the rest take the next ones;
  - an intent the emulator rejects is retried one VTXO per intent in the same
    cycle, so a bad VTXO only blocks itself;
  - scanning pauses while a batch is in flight, so keep renewal windows well
    above a few arkd rounds when many coins expire together;
  - the operator list holds 10,000 delegations in a 70 ms, 3.6 MB response;
    the UI shows the 300 most urgent and searches the rest.
  What does not scale out: one instance per key (the cosigner key signs one
  tree at a time).

## Security model

What each party can and cannot do to coins at a delegate address:

| party | can | cannot |
|---|---|---|
| anyone on the public API | register scripts, read a delegation they know the address of, fill the delegation cap | move or block anyone's coins |
| the owner (holder of an exit key) | stop and resume the delegation of their address; exit unilaterally | anything to other addresses |
| the delegatee operator (this service, or whoever holds its key) | stop renewing (the owner then exits with their own key); take up to `maxFee` each time a coin is renewable, see [Fees](#fees) | send coins anywhere but back to the same script |
| arkd | refuse service; charge fees, which the owner caps with `maxFee` | get a forfeit without delivering the new VTXO: before signing any forfeit the service checks that the batch's VTXO tree is well formed, hangs off the commitment tx, pays every renewed coin (script, amount and assets) in its own leaf, and that the connectors come from that same tx |
| the emulator | refuse to co-sign | sign alone: the delegate leaf also needs arkd's key |
| **arkd and the emulator together** | **spend the delegate leaf**: it is a 2-of-2 between them, the covenant is only enforced by the emulator's honesty | touch the owner's exit leaf |

So delegating means trusting that the arkd operator and the emulator operator
do not collude, exactly like any other emulator-enforced Arkade script. The
owner's unilateral exit is the way out of every failure above, as long as
they come back before expiry.

Known limits: the half-life rule for fee-paying delegations is enforced by
the service rather than the covenant, and admin credentials are file-backed
and require a restart to change.

## Repository Structure

- [`api-spec`](./api-spec/): protobuf definitions, generated stubs and OpenAPI spec
- [`cmd/delegateed`](./cmd/delegateed/): entrypoint
- [`internal/config`](./internal/config/): environment config and service wiring
- [`docs/protocol.md`](./docs/protocol.md): covenant, renewal flow, where spending templates will plug in
- [`internal/core/application`](./internal/core/application/): covenant, scanner and renewal flow
- [`internal/core/domain`](./internal/core/domain/): delegation model and repository interface
- [`internal/infrastructure/db/postgres`](./internal/infrastructure/db/postgres/): sqlc queries and migrations
- [`internal/interface/grpc`](./internal/interface/grpc/): gRPC server, JSON gateway, handlers, operator UI (`web/index.html`)
- [`test/e2e`](./test/e2e/): end-to-end tests against a regtest stack

## Development

### Compile binary from source

```sh
make build
```

### Local Development Setup

Everything needed for regtest is in [docker-compose.regtest.yml](docker-compose.regtest.yml):
bitcoin and the explorer come from [nigiri](https://github.com/vulpemventures/nigiri),
the rest (nbxplorer, arkd-wallet, arkd v0.9.13, emulator v0.0.8-rc.1, postgres)
from the compose file. `make regtest-up` also runs
[scripts/regtest-init.sh](scripts/regtest-init.sh), which creates, unlocks and
funds the arkd wallet through its admin API (port 7071).

```sh
make regtest-up     # nigiri + arkd + emulator + postgres
make run            # delegateed from source on :7080, operator UI on http://localhost:7081/
make regtest-down
```

`make regtest-run` starts the same stack with `delegateed` in docker instead.
The arkd and emulator services are the same as in the emulator repo and use
the same container names and ports, so stop one stack before starting the
other. `EMULATOR_VERSION` overrides the emulator image tag.

### Testing

```sh
make test       # unit tests, offline, with coverage per package
make test-e2e   # regtest stack must be up; recreates postgres, runs the repository tests, then real renewals
```

The unit tests run the service against in-memory fakes of arkd, the indexer,
the emulator and the repository: registration rules, scanning, fee handling,
failure bookkeeping, the cosigner role against a real MuSig2 coordinator, and
the pre-forfeit batch checks against real transaction trees, including the
batches a dishonest arkd could propose. The gRPC, REST, UI and per-operator admin auth
paths are tested on real ports over a fake service.

The e2e suite funds wallets through the faucet and covers, against the real
arkd, emulator and postgres:

- two consecutive renewals of one VTXO (offchain tx → batch leaf → batch
  leaf), an asset VTXO, the operator API and UI port;
- ten delegations renewed in one batch, and 128 spread over eight intents of
  one batch (twice what is built and finalized at once);
- several coins at one address, two of the same amount included;
- several renewal windows, including one too far from expiry to be touched;
- arkd charging intent fees: a delegation that accepts the fee (with and
  without an asset, renewed once and not every round), one that refuses it,
  and a refused coin going through once the fee drops;
- cancelling really stops renewals, registering again resumes them;
- a restart with the same key picks up coins funded while it was down, while
  an instance with another key leaves them alone and reports them as foreign;
- stopping mid-renewal finishes the batch first;
- the wallet flow over plain REST, as documented above.

### Protobuf and SQL generation

```sh
make proto                 # regenerate stubs and OpenAPI spec with buf
make pgsqlc                # regenerate sqlc queries
make FILE=name pgmigrate   # create a new migration pair
```
