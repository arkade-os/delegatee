# Handoff: state of delegateed, 2026-09-20

For whoever (or whatever) continues this work. `README.md` is the user
guide, `docs/protocol.md` the covenant reference, `AGENTS.md` the rules for
changing the code. This file is the rest: what exists, why it is the way it
is, what is unfinished, and what was deliberately not done.

## Where things stand

The service is feature-complete for its scope and verified locally:

- unit tests: ~90% of own code, offline, race-clean (`make test`);
- e2e: 11 scenarios against real arkd v0.9.13 + emulator v0.0.8-rc.0 on
  regtest, plus repository tests against postgres (`make test-e2e`, ~8 min);
- `golangci-lint`, `govulncheck` and Trivy (same flags as CI) are clean;
- the docker image builds and starts.

It is **not yet deployed anywhere**, and CI has not run on it: everything
above ran on one developer machine. The branch `production-ready` holds
the work in five commits on top of `master`.

### What it does, in one paragraph

A user builds a VTXO script whose "delegate" leaf is
`server key + emulator key tweaked with a covenant` and registers its
tapscripts. The covenant (`buildArkadeScript`) only lets the emulator co-sign
a batch *register* intent that sends each input back to its own script, in
the renewal window before expiry, with at most `max_fee` sats less, and with
this service's key as the only tree cosigner. Every `POLL_INTERVAL` the
service scans the indexer for coins at registered addresses, prices them with
arkd's current fee programs, builds intents, has the emulator co-sign, joins
the batch as tree cosigner, verifies the batch, and finalizes forfeits. The
owner keeps its forfeit and exit leaves and can revoke the delegation with a
signature from the exit key.

## Decisions and why

| decision | why | where |
|---|---|---|
| fees are paid from the coin, capped by a user-chosen `max_fee` in the covenant | the alternative (service sponsors fees from its own wallet) needs a funded wallet and a way to get paid back; the cap keeps a dishonest operator's take bounded and visible | `covenant.go`, `renewalOutput` |
| the `max_fee = 0` script is byte-identical to the first release | addresses pin the script; changing it strands coins | `covenant_test.go` golden vectors |
| a fee-paying delegation is never renewed in the first half of a vtxo's life | seen on regtest: window ≥ lifetime made the *honest* service renew, and pay, every round (5,000 → 4,400 sats in 30 s) | `dueAt` |
| the batch is verified before any forfeit is signed | the SDK does this for online users; the custom batch handler skipped it, so a dishonest arkd could have collected forfeits without delivering the new coins | `validateBatch`, `leavesPay` |
| no policy/plugin abstraction | a teammate is building a template system where the user passes a description of how the contract may be spent; it replaces the hardwired covenant rather than extending a registry, so a plugin layer was removed | `TODO(templates)` in `covenant.go`, `docs/protocol.md` |
| admin port serves public API + admin API + UI + metrics, without CORS | the UI needs a single origin; a CORS wildcard on the admin port let any page in the operator's browser cancel delegations | `internal/interface/grpc/service.go` |
| admin auth is file-backed per-operator HTTP Basic auth | native browser prompt, zero UI code, works for gRPC clients, bcrypt hashes never need to be sent to the service | `basicAuth`, `loopbackAuth` |
| `revoked` (owner) vs `cancelled` (operator) statuses | operators need to know why a delegation stopped | `domain.DelegationStatus*` |
| failures recorded once per distinct error; history pruned after 30 days keeping each delegation's latest row | a stuck coin wrote a row and an error log every poll; pruning must not hide a still-failing delegation | `renewAndRecord`, `PruneRenewals` |
| derived per-delegation data cached across scans | 1.4 s of CPU per scan at 5,000 delegations, 1.4 ms with the cache | `service.watched`, `BenchmarkScan5000` |
| indexer chunks, intent building and forfeit finalization run 4 at a time | finalization sits inside arkd's forfeit deadline; the rest hides latency | `concurrency`, `errgroup` |
| operator list omits tapscripts; UI renders the 300 most urgent rows | 10,000 delegations → 70 ms / 3.6 MB response, page stays usable | `ListDelegations`, `MAX_ROWS` |
| `DELEGATEE_MAX_DELEGATIONS` cap | every active delegation costs an indexer lookup per poll; a flood of junk registrations would delay real renewals; hitting a cap is the safer failure | `ErrFull` |

## Security model, short

- Anyone on the public API: register scripts, read a delegation by address,
  fill the cap. Cannot move or block coins.
- The operator (holder of the configured secret keyring): stop renewing; take up to
  `max_fee` each time a coin is renewable. Cannot send coins elsewhere.
- arkd: refuse service; charge fees (capped by `max_fee`). Cannot get a
  forfeit without delivering the new vtxo (`validateBatch`).
- The emulator: refuse to co-sign. Cannot sign alone.
- **arkd and the emulator together can spend the delegate leaf** (2-of-2).
  Inherent to emulator-enforced scripts; documented in the README.
- The owner always has the unilateral exit.

Known residuals: the half-life rule is enforced by the honest service only,
the covenant cannot (no age opcode in the emulator, worth requesting), and
admin credentials are file-backed and require a restart to change; operators
that terminate auth outside the service can explicitly disable this layer.

## What is left

Ordered by what blocks production.

1. **Review and merge.** Have someone who knows arkd and the emulator read
   `validateBatch` and `buildArkadeScript` with the fee branch. These are the
   two places where a mistake costs users money.
2. **CI.** `test.yaml` runs `make test` and `make test-e2e` on `regtest-up`;
   neither has run on a runner yet. Expect ~8 min for the e2e job.
3. **A network other than regtest.** `test/e2e/mutinynet_test.go`
   (`TestLiveDelegatee`, needs `DELEGATEE_URL` and `ARK_URL`) has not been
   run since the pre-forfeit check was added. Partial trees streamed by other
   arkd versions could make `validateBatch` reject (fails safe: no forfeit,
   no renewal).
4. **Client side.** Nothing in the Arkade wallet or ts-sdk speaks this
   protocol; they integrate fulmine's older "delegator" (pre-signed intents,
   3-of-3 leaf, fee address). See "Client work" below.
5. **Agree two formats with the wallet team** before they ship: the
   revocation message (`tagged_hash("delegatee/revoke", "<address>:<ts>")`,
   ±10 min) and the rule that `renewalWindow` stays well below the VTXO
   lifetime when `maxFee > 0`. The service documents the rule; only a wallet
   can enforce it.
6. **Key management.** Rotation is supported with a keyring: the first key
   is active for new addresses and retained keys renew existing addresses.
   Remove old keys only after their addresses have been migrated or retired.
7. **Admin credential lifecycle.** The users file has per-operator bcrypt
   credentials, but changes require a restart and there is no audit trail.
8. Nice to have: server-side pagination of `ListDelegations` (fine at 10k,
   not at 100k); failure dedupe survives restarts (today a still-failing coin
   is recorded once more after each restart); gzip on the admin list.

## Client work (wallet + ts-sdk)

Today's client model vs. this service:

| | fulmine delegator (today) | delegateed |
|---|---|---|
| delegate leaf | `user + delegate + server` | `server + tweaked emulator key`, no user key |
| user signs | register intent + forfeits, pre-signed at startup | nothing; registers tapscripts once |
| after a renewal | coin undelegated until the user pre-signs again | renewed indefinitely |
| fee | paid to a delegate address | `max_fee` in the address, taken from the coin |
| info | `GET /v1/delegator/info` | `GET /v1/info?renewalWindow&maxFee` |
| stop | — | `POST /v1/delegate/{address}/revoke` |

ts-sdk needs: the emulator key tweak
(`xonly(P) + tagged_hash("ArkScriptHash", script)·G`), a byte-exact TS port of
`buildArkadeScript` (golden vectors in `covenant_test.go`) so wallets verify
the covenant instead of trusting the response, a script class with forfeit +
exit + delegate leaves, a contract handler whose params re-derive the script
(`pubKey, serverPubKey, emulatorPubKey, delegatePubKey, renewalWindow,
maxFee, csvTimelock`), a REST provider for the four public endpoints, and
revocation signing with the identity's exit key. The pre-sign flow
(`DelegateManager.delegate`) has no equivalent.

Wallet needs: settings that validate `serverPubkey` against the ASP,
`emulatorPubkey` against the emulator, and the rebuilt covenant; choice of
`maxFee`/`renewalWindow` with the lifetime rule enforced; a one-time
self-send of existing coins to the delegatee address on enabling; a status
view from `GET /v1/delegate/{address}` (renewal history carries the reason a
coin is not renewed); revoke on disabling; the new contract type in backup.
Decide whether delegateed replaces the fulmine delegator behind the existing
toggle or coexists behind a new one.

## Operating notes

- `POLL_INTERVAL` well under the smallest window users pick;
  `RENEWAL_TIMEOUT` above the arkd session period; termination grace period
  ≥ `RENEWAL_TIMEOUT` (shutdown waits for the in-flight batch).
- Alert on `delegatee_vtxos_late > 0` and on `/healthz` (includes a
  `scanner` check: no scan for max(3 polls, 1 min) outside a batch).
- The UI's "Needs attention" list shows failed, late and foreign-key
  delegations with the reason.
- Regtest: `make regtest-up`, `make run`, UI at http://localhost:7081/. The
  compose stack shares names and ports with the emulator repo's: run one.
- To eyeball the UI with data, register delegations against `:7080` from a
  throwaway e2e test and screenshot with headless Chrome
  (`--blink-settings=preferredColorScheme=1` for light mode).

## Test map

| file | covers |
|---|---|
| `application/covenant_test.go` | param bounds, golden scripts, `dueAt` incl. half-life, `renewalOutput` |
| `application/service_test.go` | registration rules and cap, scan holdings/status, failures recorded once, health, start/stop, late + scanner health |
| `application/renewal_test.go` | fee pricing and refusal, per-vtxo retry, previous-tx lookup, asset packet, batch handler selection, forfeit building |
| `application/batch_test.go` | `validateBatch` against real trees incl. dishonest batches; full MuSig2 round with a coordinator; finalization |
| `application/revoke_test.go` | owner revocation, every rejection path |
| `application/scale_test.go` | request counts at scale; `BenchmarkScan5000` |
| `application/fakes_test.go` | in-memory repo/arkd/indexer/emulator, `newTestEnv` |
| `grpc/service_test.go` | real servers over a fake service: routing, CORS, UI, metrics, password, rate limit |
| `grpc/handlers/handlers_test.go` | every handler and error → status code mapping |
| `postgres/postgres_test.go` | lifecycle, history, prune rule (needs postgres) |
| `test/e2e/*` | see README "Testing" |
