# swiyu: the lab verifier for the Swiss wallet

`SwiyuVerifier` is [`polaris-oid4vp`](../../../packages/polaris-oid4vp/)'s `Verifier`, asking for a presentation the way the
swiyu wallet reads a request. The request side is this folder's. The response side is the package's, unmodified:
`handle_direct_post` is not overridden (a test holds that), and three lab checks sit beside it that can only refuse.

## Result, 2026-11-13

On 2026-11-13 the swiyu Sandbox Wallet 1.19.0 (iOS), operated by the author and holding a Beta-ID from the Beta
Credential Service, answered a request from this verifier at `c5b0ba5f`. The package's `handle_direct_post`, with
`accept_vp_token_as_json_string=True`, answered `200 authentic`. L7, L10 and L13 each said `ok`, and the issuer's
status list, read from the registry and held to the issuer's pinned key, said VALID.

Offline, a second implementation, `@sd-jwt/sd-jwt-vc` 0.24.3 (OpenWallet Foundation Labs), accepts the same
presentation under the pinned issuer key with the request's nonce and audience. It refuses it under another nonce,
with no key, and under each of the 17 other pinned keys.

## What the request carries

| | |
|---|---|
| client identifier | `decentralized_identifier:` plus the verifier's `did:webvh` DID; `iss` equals it |
| request object | ES256, header exactly `alg`, `typ` `oauth-authz-req+jwt`, `kid` (an absolute DID URL), `profile_version` `swiss-profile-verification:1.0.0`; no `x5c` |
| `client_metadata` | `jwks` (one P-256 key, `alg` ECDH-ES) and `encrypted_response_enc_values_supported: ["A256GCM"]`, nothing else |
| link | `client_id` and `request_uri` only, percent-encoded, in both schemes (`openid4vp://`, `swiyu-verify://`); the request is fetched by GET (the listener also answers a POST to `/request.jwt`) |
| query | one `dc+sd-jwt` credential query, `vct_values` both type names of the Beta-ID, one claim (`age_over_18`); `redirect` off; no transaction data |
| variants | `A` no statement, `dcql_query` sent. `B` the identity trust statement carried. `C` identity and verification query statements carried, `scope` sent in place of `dcql_query` |

The session, the nonce, the per-request encryption key and the DCQL query builder are the package's.

## The three checks beside the package

| | where | what it refuses |
|---|---|---|
| L7 | `Front`, in front of `handle_direct_post` | a response whose JWE header says an `enc` other than `A256GCM`, before the package decrypts it; the token is read as the package reads it, with surrounding whitespace removed |
| L10 | the `_single_presentation` override, which calls the package's first | a credential whose header has no `kid`, or a `kid` that is not an absolute DID URL of the pinned issuer; the reported issuer is the `kid`'s DID and `iss` decides nothing |
| L13 | the `status_resolver` the package already calls | a status list not on the configured registry host, over 200 KB, or behind a redirect; a token whose `kid` is not a pinned key of the credential's own DID |

A lab check may refuse what the package would accept and never accepts what the package refuses
(`test_lab_checks_only_refuse`). Each response the listener hands to the verifier leaves a record (the package's listener refuses some POSTs
before they reach it, and a record that cannot be written raises). `verdict` is the answer `handle_direct_post` gave as run, the
lab checks inside it, or, when L7 refused before the package ran, the lab's own refusal. Each check carries its `outcome` and a `parent`: the package's own answer at the place that check sits
(L7: its status and code, or `not judged` when L7 stopped the response; L10: `passed` when the package's `_single_presentation`
returned the presentation, its refusal when it did not, or `not judged` when L7 stopped the response or the package never reached
`_single_presentation`; L13: the answer of `status.decide_by_fetching`, or `not judged` when the lab did not reach it). A check
that did not run is `not judged`. `status` is the issuer's list as the verdict carries it, or as L13 read it, with `stale` (the package's reading of the token's ttl from its iat, kept, not counted on) and
`age_seconds`, or
`not judged` when neither the verdict nor L13 has an answer. `counted` is true only when the package accepted the presentation, L7, L10 and L13 each said `ok`, and the list says
VALID and was issued at most 24 hours before it was read (`COUNTED_MAX_LIST_AGE_SECONDS`, the lab's own policy,
declared 2026-11-13). `package` names what judged: version, file (relative to the repository root), the commit of its folder and
whether its folder held uncommitted changes (`dirty`; `unknown` when git does not answer). The tree's `packages/polaris-oid4vp` is
put first on `sys.path` before the package is imported. The files `record-N.json` and `capture-N.json` carry the
same N as `record["n"]`; a run on a folder that already holds records numbers past the largest one in it.

The issuer's key is a pin, a file made from the issuer's DID log checked offline (`issuer-pin.json`: `did`, `log_sha256`,
`resolver`, `resolved_at` as `2026-11-13T02:00:00Z`, and `keys`, each a P-256 JWK whose `kid` is a DID URL of `did`). A pin older
than 24 hours is refused at start. Nothing here resolves a DID or follows a name in a token to a host.

## Files

| | |
|---|---|
| `swiyu_verifier.py` | the verifier, `Front`, the pin and statement checks, the command line |
| `swiyu_fixtures.py` | keys, DID logs, pins, credentials, statements and a stand-in holder, all made in the process that uses them |
| `test_swiyu.py` | the tests: L1 to L15, the package members the subclass leans on, the scripts held against fake `curl`, `docker` and `cloudflared` |
| `dryrun.py` | the verifier on loopback and a local stand-in, end to end |
| `did.sh`, `pop.sh`, `statement.sh`, `run.sh`, `common.sh` | the owner's scripts |

## Run it

```bash
cd lab/interop/swiyu
python3 -B -m unittest test_swiyu       # needs the cryptography package; the package under test is read from packages/
python3 -B dryrun.py                    # prints "DRY RUN: a local stand-in, not a wallet, never evidence" first and last
```

The tests reach no network beyond a loopback address. Every key and credential is made in the test. The scripts are run with fake
tools first on `PATH` that record their arguments and answer from files.

## The owner's steps

`did.sh`, `pop.sh` and `statement.sh` print each request before sending it (method, URL, any token as `<redacted>`, and the
body: for the DID log upload the file's name, size and sha256, for the proof of possession a placeholder with the proof as
`<redacted>`, for a GET none), and read tokens only from environment variables exported in your own shell. `run.sh` sends no
request itself. The verifier it starts reads a presented credential's status list with a GET to `SWIYU_STATUS_HOST` (a list named
on another host is not fetched), and `cloudflared` opens the tunnel. `run.sh` prints the tunnel address, the process ids, the
verifier's `listening` line, the links, the method and path of each request the listener answers, and each result with the path of
its record. `did.sh`, `pop.sh` and `statement.sh` write under the key folder you name (set to mode 700, files mode 600); `run.sh`
writes `runs/` under it (mode 700, files mode 600). `run.sh` also keeps the tunnel's log in `$TMPDIR` while it runs and deletes it
when it stops. A script that completes prints
`done` as its last line and one that stops early does not (`run.sh` prints it when the verifier exits 0, a counted presentation).
A request that fails prints what the registry answered (its first 2000 bytes, any token or proof of possession as `<redacted>`) and stops the script.
The DID tool is `didtoolbox-2.3.0.jar`, from
`https://github.com/swiyu-admin-ch/didtoolbox-java/releases/download/2.3.0/didtoolbox-2.3.0.jar` (sha256
`e1804393b2bb56164e22cad7cf852524118f92dc9e13677ee49ca3e38bf62af1`, checked before use), run in a container pinned by digest with
no network. The image is never pulled (`--pull never`), so it must already be present:
`docker pull gradle:8.14.3-jdk21@sha256:21bd311ed01360c189b8870c6b6e988199ff10f72d445d02fb39d3cff9da91d7` fetches it once. Set
`PYTHON` to an interpreter that has the `cryptography` package.

1. `did.sh KEYDIR JAR` makes the DID. It lists your DID spaces, runs the DID tool offline to write `did.jsonl` and the key files
   into `KEYDIR`, and uploads the log. Needs `SWIYU_IDENTIFIER_REGISTRY_ACCESS_TOKEN` and `SWIYU_PARTNER_ID`.
2. In the portal, start profile verification up to the step that asks for a proof of possession.
3. `pop.sh KEYDIR JAR` fetches the challenge, signs it offline and submits the proof. Needs `SWIYU_TRUST_REGISTRY_ACCESS_TOKEN`.
4. `statement.sh KEYDIR identity` fetches the identity trust statement the registry holds for your DID (an anonymous GET).
   `statement.sh KEYDIR vqps SCOPE` submits the verification query statement and saves it (optional; needs the trust token).
5. Put `issuer-pin.json` in `KEYDIR`.
6. `run.sh KEYDIR VARIANT WALLET_VERSION` starts a quick tunnel (`cloudflared`, no account), starts the verifier on the tunnel's
   origin and prints the links, and a QR if `qrencode` is on `PATH`. Scan with the wallet. `Ctrl-C` stops the tunnel and the
   verifier and deletes the tunnel's log. The record and the private capture are written under `KEYDIR/runs/`.
   Optional: `PORT`; `SWIYU_REGISTRY_HOST`, the host of your DID, default `identifier-reg.trust-infra.swiyu-int.admin.ch` (the
   verifier refuses to start when your DID is on another host, so set it for one); `SWIYU_STATUS_HOST`, the registry host of the
   credential's status list, default `status-reg-a.trust-infra.swiyu-int.admin.ch`.

Try the variants in the order `C`, `B`, `A`, each at most twice.
