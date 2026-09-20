# Protocol

Low-level reference for wallet and service developers. For usage, start with
the [README](../README.md).

## The delegate VTXO

A taproot output with two kinds of leaves:

| leaf | script | who can use it |
|---|---|---|
| delegate | `<arkd signer> CHECKSIGVERIFY <emulator key tweaked with the covenant> CHECKSIG` | anyone holding a transaction the covenant accepts; in practice this service |
| exit | `<csv> CSV DROP <user key> CHECKSIG` (any standard Arkade exit closure) | the user, unilaterally |

The emulator signs with `emulator_key + H(arkade_script)·G` only after running
`arkade_script` against the transaction it is asked to sign. Nobody holds a
key that spends the delegate leaf unconditionally, so the covenant is the
entire trust model: read it before trusting a delegatee.

## The renewal covenant

Parameters: `delegate_pubkey` (this service's vtxo tree cosigner key, hex,
compressed), `renewal_window` (seconds), `max_fee` (sats).

```
OP_PUSHEXPIRY <renewal_window> OP_SUB OP_CHECKTIMEVERIFY
"type"                    OP_INSPECTINTENTMESSAGE OP_VERIFY "register" OP_EQUALVERIFY
"onchain_output_indexes"  OP_INSPECTINTENTMESSAGE OP_VERIFY "[]"       OP_EQUALVERIFY
"cosigners_public_keys.0" OP_INSPECTINTENTMESSAGE OP_VERIFY <delegate_pubkey hex> OP_EQUALVERIFY
"cosigners_public_keys.1" OP_INSPECTINTENTMESSAGE OP_NOT OP_VERIFY OP_DROP
```

followed, when `max_fee` is 0, by

```
OP_PUSHCURRENTINPUTINDEX OP_1SUB <7: script|value|assets> 0 OP_TUNNEL
```

and otherwise by

```
OP_PUSHCURRENTINPUTINDEX OP_1SUB OP_INSPECTOUTPUTVALUE <max_fee> OP_ADD
OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE OP_GREATERTHANOREQUAL OP_VERIFY
OP_PUSHCURRENTINPUTINDEX OP_1SUB <5: script|assets> 0 OP_TUNNEL
```

What it enforces on the intent proof spending the VTXO as input *i*:

1. it is within `renewal_window` seconds of the VTXO's expiry;
2. it is a batch **register** intent with no onchain output, so the funds stay offchain;
3. the only vtxo tree cosigner is `delegate_pubkey`, so nobody else can cosign
   (and later sweep-dodge) the new leaf;
4. output *i−1* has the same script and the same assets as the input
   (`OP_TUNNEL`), and its value is the input's, minus at most `max_fee`.

What it does **not** enforce: who receives the difference when `max_fee` > 0
(the intent may carry other inputs and outputs), nor the VTXO's lifetime.
So `max_fee` is the most a dishonest delegatee can take per renewal, and a
renewal is possible whenever rule 1 holds: wallets must keep `renewal_window`
well below arkd's batch expiry, or the coin is renewable in every round.

Input 0 of an intent proof is the BIP-322 message input, hence the `i−1`.

The zero-fee script is kept byte-identical to the first release so existing
addresses don't move; [covenant_test.go](../internal/core/application/covenant_test.go)
pins both variants.

## Renewal flow

Every `POLL_INTERVAL`:

1. list active delegations, query the arkd indexer for their spendable VTXOs;
2. keep the VTXOs that are due: inside `renewal_window`, and, when
   `max_fee` > 0, past half of their life, so that a window longer than the
   VTXO lifetime does not pay a fee in every round;
3. read arkd's intent fee programs (`GetInfo`) and price each VTXO: input fee
   plus output fee at the actual output amount, each rounded up. The service
   solves that fee/output dependency and rejects non-convergent or invalid
   fee programs. A VTXO whose fee exceeds its `max_fee` is dropped here with
   a recorded failure, so it cannot sink an intent;
4. build intents of up to `MAX_VTXOS_PER_INTENT` inputs, output *i−1* paying
   input *i*, attach the asset packet and the emulator packet (one covenant
   entry per input), and have the emulator co-sign each (`SubmitIntent`). A
   rejected intent is retried one VTXO at a time;
5. register every intent with arkd, then follow batch sessions with a single
   tree signer until all intents have been included;
6. at finalization, **before signing anything**, check what arkd proposes
   (`validateBatch`): the VTXO tree is valid for the commitment tx and spends
   its batch output, each renewed coin has its own leaf output with the exact
   script, amount and assets, and the connector tree is rooted in the same
   commitment tx. Otherwise no forfeit is produced and the renewal fails;
7. build one forfeit per VTXO, have the emulator and arkd
   sign them (`SubmitFinalization`, `SubmitSignedForfeitTxs`);
8. record one renewal row per delegation and outcome.

Fees are paid implicitly, as in any Ark intent: `sum(inputs) − sum(outputs)`.

## Other delegation logics

Only the renewal covenant exists, and it is hardwired on purpose. A template
system is being designed in which the user hands the delegatee a description
of how their contract may be spent; it will replace the fixed covenant rather
than sit next to it, so no plugin layer was built ahead of it.

What a template will take over is already isolated in
[covenant.go](../internal/core/application/covenant.go) (see its
`TODO(templates)`): the covenant itself (`buildArkadeScript`), when to act
(`dueAt`), what the intent pays (`renewalOutput`) and the bounds on user
params (`validateParams`). The batch plumbing in `renewal.go` does not know
about renewals, with one assumption to lift when needed: proof input *i* is
paid by output *i−1*.

Whatever comes next, never change the script the current params produce: it
would move every registered address.
