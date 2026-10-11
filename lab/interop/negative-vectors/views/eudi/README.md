# Record 018's negative vectors in the EU verifier endpoint's test-resource layout

**What this is:** Polaris-generated negative vectors (lab record 018), rendered in the EU verifier endpoint's test-resource layout, each with its expected outcome and the spec clause it cites.

**What this is not:** the EU project's own vectors. The EU project has not run them, and nothing here claims how their verifier behaves.

`make_vectors.py --out` writes this directory from `vectors.json`'s generator; never edit it by hand.

## Files

The layout is the one in `src/test/resources/` of eu-digital-identity-wallet/eudi-srv-verifier-endpoint at df07af2f.

- `NN-<id>-dcql.json`: the transaction-init body: `dcql_query` (one `dc+sd-jwt` query, id `pid`, vct `urn:eudi:pid:1`), `nonce`, `request_uri_method`.
- `NN-<id>-vpToken.json`: `{"pid": [<presentation>]}`.
- `INDEX.json`: per vector, `expected` (`accept` or `reject`), `clauses` (the spec text), `trust` and `files` (its pair).

25 vectors, numbered 50 to 74 in `vectors.json`'s order. The 2 `accept-*` controls come first: a refusal counts only where the controls are accepted.

## The binding

Every Key Binding JWT names `aud` `x509_hash:WJfeA4xR3mvFsWk2fEB3oiu4f3E1yBHkXjsN0P2s6RE`, `nonce` `nV7cX2q-0bQ5mT9sKe4wLz` and the instant 2026-10-01T00:00:00Z (1790812800). A verifier with another client_id, nonce or clock refuses even the controls.

## Bind them to the EU test harness

Its KB-JWT check reads the verifier's clock (`kbJwt.clock.skew` PT5S), so no committed view stays bound. Make one just before the run (it lands in `DIR/views/eudi/`):

```bash
python3 make_vectors.py --audience x509_hash:i7jZiSqa4GXNh1LzBwD2lVtKIcIhpinRQRo8BHSVMx0 --nonce 706f6c4d-c92d-4472-9dbf-d814c94f90c2 --now "$(date +%s)" --out DIR
```

and configure the harness with:

- `verifier.clientIdPrefix=x509_hash` and `verifier.originalClientId=i7jZiSqa4GXNh1LzBwD2lVtKIcIhpinRQRo8BHSVMx0`, as their InitDCApiTransactionTest does. The default client_id (`pre-registered`) has no Client Identifier Prefix, which `kb-aud-no-prefix` needs.
- The test root in `INDEX.json`'s `settings.trust_anchors_pem` as an issuer trust anchor: every x5c chain ends there, whichever key `--issuer-key` signs with. `accept-jwks` also needs `settings.issuer_jwks`; without it, run the `trust: x5c` vectors.
