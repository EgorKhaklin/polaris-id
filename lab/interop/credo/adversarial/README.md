# Adversarial round: mutations of genuine wallet presentations

**Reader:** anyone asking whether `polaris-oid4vp` refuses bad input from implementations other
than its own test wallet. **Result, 2026-09-27:** 42 cases over each of two wallets' real
output (Credo 0.6.3 and walt.id Wallet API v2). The first run found one defect, the same case
in both. It was fixed that day, and all 42 now behave as expected for both wallets.
**2026-09-28:** the same 42 over two more wallets' real output, eudi-dev v2.3.7
([`eudi-dev/`](eudi-dev/)) and OID4VCgo v0.12.0 ([`oid4vcgo/`](oid4vcgo/)), the second with a
credential it issued itself under an `x5c` chain and an `exp`: 42 of 42 as expected for each, no
new defect.

## What was done

1. `present.ts` ran as in [`../README.md`](../README.md): an unmodified Credo 0.6.3 agent
   built, signed and encrypted a presentation and POSTed it. The verifier was the tree's
   `polaris-oid4vp`, started through [`capture-verifier`](capture-verifier), which is the CLI
   unchanged plus one hook. Before judging, the hook records the posted JWE, the body it
   decrypts to, and the session it answers (nonce, state, the per-request decryption key).
   Credo's output was accepted.
   walt.id was captured the same way, through its own procedure
   ([`../../waltid/README.md`](../../waltid/README.md)) with `serve` started through the hook.
2. [`adversarial.py`](adversarial.py) rebuilds that session inside a `Verifier` that judges
   against the captured `client_id`. The genuine response goes first, as the control that must be accepted. Then 37
   mutations of Credo's output go through the full `handle_direct_post` path (the second
   control, the genuine body re-encrypted, is also accepted), and three freshness cases go to
   `verify_presentation` with a moved `now` (at `iat`: accepted; a day either side: refused):
   - at the JWE layer: ciphertext, tag and IV altered, protected-header changes, extra
     segments;
   - in the response body: `state`, and the shape and key of `vp_token`;
   - in the SD-JWT: the KB-JWT removed, unsigned, re-aimed or altered; disclosures withheld,
     reordered, repeated, invented, altered or padded; the issuer JWT altered.
   [`results.json`](results.json) and [`waltid/results.json`](waltid/results.json) are the
   tables, with the reason each refusal gave the operator. [`capture.json`](capture.json) and
   [`waltid/capture.json`](waltid/capture.json) are the inputs, so the round reruns without
   either wallet and without any PKI on disk. The private key in each capture decrypted one
   request that no longer exists, and the data is the notional test identity.

    cd lab/interop/credo/adversarial
    python3 adversarial.py capture.json --out results.json      # needs `cryptography`
    python3 adversarial.py waltid/capture.json --out waltid/results.json \
        --wallet "walt.id Wallet API v2 (waltid/wallet-api2:1.0.0)"
    python3 adversarial.py eudi-dev/capture.json --out eudi-dev/results.json \
        --wallet "eudi-dev v2.3.7 (ghcr.io/dominikschlosser/eudi-dev:v2.3.7)"
    python3 adversarial.py oid4vcgo/capture.json --out oid4vcgo/results.json \
        --wallet "OID4VCgo v0.12.0 (github.com/idfoundry/oid4vcgo, cmd/conformance-wallet-vp)"

**Every replay is judged at the instant the wallet presented** (2026-09-28). The verifier judges
a key binding JWT's `iat` inside a 300 second window, and an `x5c` leaf's validity, against the
clock. Until the harness pinned the clock to the capture's `iat`, a round rerun later refused the
genuine response as stale, which is loud, and refused two mutations ("one disclosure withheld",
"disclosures reordered") on freshness instead of on `sd_hash`, which is silent: they still counted
as caught while no longer testing what they name. Measured on the Credo capture nine hours old.
Pinned, it reproduces its committed results exactly, reasons included. The capture hook now also
records `x5c` trust anchors, which the replay passes on.

To capture afresh, run `present.ts` with `POLARIS_OID4VP=$PWD/adversarial/capture-verifier`
and `CAPTURE=<file>`, with the tree's `polaris-oid4vp` importable by the `PYTHON` given (an
editable install works). `present.ts` rewrites `evidence/positive/`; restore it afterwards,
because that directory records the PyPI release, not the tree.

## The finding

**A `vp_token` keyed by a query id the request never used was accepted.** The request's DCQL
names its one credential query `pid`, and OpenID4VP 1.0 section 8.1 keys `vp_token` by that
id. The verifier checked that the object held exactly one entry and never compared the key,
so `{"not-pid": [<genuine presentation>]}` was taken as the answer. The effect is narrow,
because the presentation still has to pass every other check. It is still a response to a
question the verifier did not ask, and the refusal message already claimed the check ("not
one presentation for the one credential the DCQL query asked for"). Fixed in
`Verifier._single_presentation` (the key must equal `Verifier.DCQL_QUERY_ID`), with a
regression test in `test_verifier.py` that fails without the fix; on the old code this round
fails that one case for either wallet's capture. After the fix, both wallets' genuine
presentations are still accepted end to end, since both key their answer `pid`. `polaris-oid4vp 1.0.0rc7`,
the certified release, carries it (SECURITY.md).

## What this does NOT establish

- **Every mutation is Polaris editing Credo's output.** Credo is an honest wallet. What was
  tested is the verifier against another implementation's real encodings, which is internal
  evidence. It is not a finding from outside, and it goes in the internal half of the
  scoreboard.
- **Nothing that needs the holder's key.** Credo's key stays in Credo's KMS, so no case
  re-signs a KB-JWT. A changed nonce, audience or `sd_hash` is refused by the signature before
  the claim is compared. The freshness cases reach the claim check only because they move
  `now` instead of the token.
- **Two wallets, one credential type, one run each.** The credential is the lab's own
  `issue_sdjwt_vc.py` output in both cases; the wallets' contribution is the presentation.
