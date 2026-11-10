# delegateed

Alpha software: use at your own risk.

`delegateed` renews Arkade VTXOs and boards bitcoin while their
owner is offline. A wallet registers a delegation on its address; every spend is
co-signed by the [emulator](https://github.com/arkade-os/emulator) only if it
satisfies the template's covenant.

The default templates in [`templates/`](templates) (`renew`, `board` for non-interactive boarding, and the VHTLC claim stream `claim`) are registered at startup.

## Run

```sh
make regtest-up   # nigiri, arkd, emulator, postgres
make run          # UI on http://localhost:7081/
make test         # unit tests
make test-e2e     # end-to-end tests on the regtest stack
make regtest-down
```

In production use `ghcr.io/arkade-os/delegatee` with the variables below.
Port 7080 is the public API
([service.proto](api-spec/protobuf/delegatee/v1/service.proto)), 7081 the
admin API and UI: keep it private. Back up the cosigner and encryption keys.

## Configuration

| Variable | | Default |
|---|---|---|
| `DELEGATEE_ARK_URL` | arkd gRPC address | required |
| `DELEGATEE_EMULATOR_URL` | emulator gRPC address | required |
| `DELEGATEE_ELECTRUM_URL` | Electrum server, `tcp://host:port` or `ssl://host:port` | required |
| `DELEGATEE_DATABASE_URL` | postgres DSN | required |
| `DELEGATEE_COSIGNER_KEY` | private key cosigning arkd's vtxo trees, 32 bytes hex | required |
| `DELEGATEE_ADMIN_AUTH` | `file` or `disabled` | required |
| `DELEGATEE_ADMIN_USERS_FILE` | `user:bcrypt` lines | with `file` |
| `DELEGATEE_ENCRYPTION_KEY` | ECIES key for template secrets, hex; a secret is sealed to the key and the id of its template | unset |
| `DELEGATEE_DEFAULT_TEMPLATES` | register the default templates at startup | `true` |
| `DELEGATEE_MIN_DELEGATION_EXPIRY` | minimum lead of a delegation's expiry | `24h` |
| `DELEGATEE_EXPIRY_INTERVAL` | how often delegations past their expiry are marked | `1m` |
| `DELEGATEE_OFFCHAIN_CONCURRENCY` | offchain attempts in flight at once | `8` |
| `DELEGATEE_ATTEMPT_TIMEOUT` | building and signing an offchain attempt, before arkd is called | `1m` |
| `DELEGATEE_RETRY_DELAY` | before the coins of a failed attempt are tried again | `1m` |
| `DELEGATEE_INTENTS_PER_BATCH` | intents arkd takes per batch: at most that many are kept registered | `128` |
| `DELEGATEE_INTENT_TIMEOUT` | an intent no batch selected by then is deleted from arkd and queued again | `5m` |
| `DELEGATEE_BAN_DURATION` | how long the coins of an intent a batch failed on keep out of the queue | `5m` |
| `DELEGATEE_LANDING_WINDOW` | after a restart, how long an attempt whose forfeits may have reached arkd waits to see its coins spent before it is failed | `5m` |
| `DELEGATEE_RESERVE` | latest a coin enters a batch, before its vtxo expires | `15m` |
| `DELEGATEE_TEMPLATE_MAX_FAILURES` | consecutive failed attempts that disable a template | `10` |
| `DELEGATEE_LOOP_STALL` | how long the loop may stay silent past a due time before `/healthz` reports it | `2m` |
| `DELEGATEE_PUBLIC_RATE_LIMIT` | requests per second per client address on the public port, loopback exempt; `0` disables | `5` |
| `DELEGATEE_MAX_DELEGATIONS` | active delegations cap | `50000` |
| `DELEGATEE_MAX_STREAM_CHILDREN` | active spawned delegations cap, apart from `MAX_DELEGATIONS` | `10000` |
| `DELEGATEE_PRUNE_AFTER` | how long after expiry a delegation a stream spawned is deleted | `720h` |
| `DELEGATEE_LOG_LEVEL` | logrus level | `4` |

The delegations a stream spawns count only toward `MAX_STREAM_CHILDREN`, the others toward `MAX_DELEGATIONS`.

Renewals are grouped. A coin's deadline is the later of its due time and its
expiry minus `RESERVE`. The earliest deadline forces a group, which carries
every renewal due by then, so they share one batch; the entries of a group are
registered one batch before it. A group over `INTENTS_PER_BATCH` splits into
consecutive batches ending at its time, the earliest deadlines first. A boarding coin
is registered at once. The reserve must be at least twice `INTENT_TIMEOUT`: one
intent that times out and a retry. The admin `GET /v1/admin/status` shows the
queue, what is registered, the coins forecast to miss their deadline and the
batches the plan expects.

A template whose attempts arkd, the emulator or the template itself
refuse `TEMPLATE_MAX_FAILURES` times in a row is disabled; a succeeded attempt
resets the count. Onchain templates
are not served.

Other limits and intervals are in [`internal/config/config.go`](internal/config/config.go).

## Streams

A template with a `trigger` is not registered by clients: the operator registers it as a stream (admin `RegisterStream`, `ListStreams`, `CancelStream`; a default with a trigger starts by itself when an encryption key is configured, and stays cancelled once the operator cancels it). The daemon reads arkd's transaction stream and, for every transaction whose extension holds the trigger's packet, captures the trigger's variables, checks the template locks the output, and spawns a delegation of the template that expires after `expires_after_seconds`. When several delegations share a script, the coins go to the one a stream spawned, otherwise to the oldest.

