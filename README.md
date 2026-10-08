# delegateed

Alpha software: use at your own risk.

`delegateed` renews Arkade VTXOs and boards bitcoin deposits while their
owner is offline. A wallet registers a watch on its address; every spend is
co-signed by the [emulator](https://github.com/arkade-os/emulator) only if it
satisfies the template's covenant.

The default templates in [`templates/`](templates) (renewal and boarding)
are registered and trusted at startup.

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
admin API and UI: keep it private. Back up the delegate and encryption keys;
the delegate key is in every delegate address.

## Configuration

| Variable | | Default |
|---|---|---|
| `DELEGATEE_ARK_URL` | arkd gRPC address | required |
| `DELEGATEE_EMULATOR_URL` | emulator gRPC address | required |
| `DELEGATEE_EXPLORER_URL` | esplora URL | required |
| `DELEGATEE_DATABASE_URL` | postgres DSN | required |
| `DELEGATEE_DELEGATE_KEYS_FILE` | delegate keys, one per line, newest first | required, or `DELEGATEE_DELEGATE_KEY` |
| `DELEGATEE_ADMIN_AUTH` | `file` or `disabled` | required |
| `DELEGATEE_ADMIN_USERS_FILE` | `user:bcrypt` lines | with `file` |
| `DELEGATEE_ENCRYPTION_KEYS_FILE` | ECIES keys for template secrets | unset |
| `DELEGATEE_DEFAULT_TEMPLATES` | register the default templates at startup | `true` |
| `DELEGATEE_MIN_WATCH_EXPIRY` | minimum lead of a watch's expiry | `24h` |
| `DELEGATEE_POLL_INTERVAL` | scan interval | `1m` |
| `DELEGATEE_RENEWAL_TIMEOUT` | intent to batch finalization limit | `2h` |
| `DELEGATEE_RENEWAL_RESERVE` | latest submission, before a vtxo expires | `6h` |
| `DELEGATEE_BOARDING_MAX_WAIT` | how long a confirmed deposit waits for a renewal batch | `10m` |
| `DELEGATEE_MAX_DELEGATIONS` | active delegations cap | `50000` |
| `DELEGATEE_LOG_LEVEL` | logrus level | `4` |

Renewals are batched: the daemon submits at the latest `RENEWAL_RESERVE`
before the first renewable vtxo expires, so every vtxo renewable by then
shares one batch session. The reserve must be at least twice
`RENEWAL_TIMEOUT`: one session that times out and a retry. A session
already running when a deadline passes delays
the retry by its own length, so set the reserve higher where sessions are
long. The admin UI shows the planned batches and why each is when it is.

Other limits and intervals are in [`internal/config/config.go`](internal/config/config.go).

## Spends

`POST /v1/spend` asks the daemon to spend given coins once through a
template, typically an offchain or intent template whose arkade scripts check
signatures the wallet put in the variables. The outpoints follow the
template's inputs. The request is signed by the owner: `pubkey` (x-only) must
be the only key of a CSV exit leaf of every input, and `signature` its BIP340
signature over `tagged_hash("delegatee/spend", id || expires_at)`, where `id`
is the spend's fingerprint (see `RegisterSpendResponse`) and `expires_at` a
big-endian uint64 at most a day ahead. The daemon retries until the coins are
spent or the spend expires; `GET /v1/spend/{id}` shows its status and attempts.
A spend never holds a coin back from a watch: a watch due to act on a coin
still does.

An output may draw from several inputs: `"value": {"from": ["a", "b"]}` pools
their satoshis, so one payment and one change can spend many coins. An input
belongs to one pool, and each pool has one output without an `amount`.
