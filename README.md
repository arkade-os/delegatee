# delegateed

Alpha software: use at your own risk.

`delegateed` renews Arkade VTXOs and boards bitcoin deposits while their
owner is offline. A wallet registers a watch on its address; every spend is
co-signed by the [emulator](https://github.com/arkade-os/emulator) only if it
satisfies the template's covenant.

The default templates in [`templates/`](templates) (renewal, boarding, VHTLC claim and refund, noninteractiveclaim, and offline_receive) are registered and trusted at startup.

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
| `DELEGATEE_MAX_STREAM_CHILDREN` | active spawned watches cap, apart from `MAX_DELEGATIONS` | `10000` |
| `DELEGATEE_LOG_LEVEL` | logrus level | `4` |

Stream delegations count toward `MAX_DELEGATIONS`; the watches they spawn count only toward `MAX_STREAM_CHILDREN`.

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

## Stream delegations

Offline receive uses `templates/offline_receive.json` as an operator stream delegation.
The receiver never registers a watch or sends its preimage to a delegatee API. Before
requesting an exact-output quote, it seals the preimage, recipient and minimum amount
to the daemon's advertised encryption public key. The operator can decrypt the preimage
and must be trusted with it. The funding transaction delivers
that ciphertext in extension packet type 4. The solver adds its payout script in TLV 2;
the daemon checks the full funding taptree and output script against the resulting
covenant claim leaf, and authenticates its recipient against the envelope before claiming.

The packet body starts with TLV 127 containing ASCII `delegatee-secrets/v1`, followed
by TLV 1 (ciphertext) and TLV 3 (compressed encryption public key). Each record is a
one-byte tag, two-byte big-endian length and value. The ciphertext uses the existing
ECIES wire format and `covclaimd/preimage/v1` domain, encrypting JSON:
`{"format":"delegatee-secrets/v1","template_id":"<content ID>","values":{...}}`.
The values are `preimage` and `receiver_program` (32-byte lowercase hex) and
`minimum_value` (canonical ScriptNum hex). Secret declarations select fields with
`field`. The recipient captured from TLV 2 must equal the authenticated receiver before
a claim can disclose the preimage. Raw ECIES plaintext remains supported by
templates without `field`, including the unchanged `noninteractiveclaim` stream.

The authenticated minimum must be positive, at most 2.1e15 satoshis, and satisfied by
the funded input before a claim can disclose the preimage. The output preserves the
input's entire value and assets and pays the authenticated recipient. This envelope
binds an intent before its quote, not a specific later refund deadline or lockup tree.
There is no encrypted claim deadline; ordinary spawned watches expire after 24 hours.

The receiver can go offline after preparing its invoice. Once the daemon receives the
funding packet, the spawned watch persists and resumes retries after a daemon restart.
The filtered indexer subscription does not replay history: funding first seen while the daemon
is unavailable cannot currently be discovered through this packet-only flow. The
indexer recovers known watches, not entirely unseen funding packets.

A template with a `trigger` is not registered by clients: the operator registers it as a stream delegation (admin `RegisterStreamDelegation`; a default with a trigger starts by itself when an encryption key is configured). The daemon opens an indexer subscription with CEL filters derived from the active triggers. For offline receive these select packet type 4, the version marker and one of its retained encryption keys. It binds matching packets, checks the template locks the output, and spawns a watch that expires after `expires_after_seconds`. Full local trigger and covenant checks remain authoritative: the CEL filter only reduces traffic. This requires indexer initial-filter support; subscription errors are reported and retried without switching to the global transaction stream.


## Capacity

Discovery filter changes update the existing subscription atomically while its
events continue to be processed. Failed or ambiguous updates are reconciled
without closing the working stream.

Known offchain direct watches use script subscriptions, split into at most 1,000
scripts per subscription. Existing shards retain their scripts as registrations
change. New and spent coin events invalidate only the affected scripts; repeated
events coalesce. The next scan queries those scripts in chunks of 100 with at
most four requests in flight. Startup, connection gaps and periodic reconciliation
refresh all active scripts. Frequent events cannot postpone the periodic refresh.

Packet discovery needs a recipient filter because a new payment's script is not
known beforehand. It uses one separate filtered subscription, with a one-event
application buffer and synchronous registration. This bounds memory, but does not
provide durable event replay or guaranteed admission during overload, a database
outage or a full registration cap. Watch rows already persisted are recoverable.

The default caps are 50,000 public/stream registrations and 10,000 spawned watches.
A successful receive watch remains active until its 24-hour expiry so it can handle
another funding to that script. Consequently 10,000 distinct receives can fill the
child cap during a day even when claims settle quickly. Raising the cap requires
capacity testing; it does not increase processing throughput.

All active registrations are still loaded and examined each scan, and direct claims
run serially within their lane. Registration inserts serialize and count active
rows. Batch planning uses sorted passes rather than repeatedly copying/scanning
remaining entries. Unit scale tests cover 50,000 scripts, bounded subscriptions,
coalesced refreshes, races and failed/reconnected streams; these use mock storage
and indexer responses and do not establish production throughput. Measure database
latency, scan duration, claim service time, oldest pending receive and cap usage
under the deployment's actual traffic before increasing limits.
