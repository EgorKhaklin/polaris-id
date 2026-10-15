# The Yivi app → polaris-oid4vp

## Result, 2026-10-14

The Yivi app (store build v8.3.1, developer mode) presented a Yivi-issued SD-JWT VC to
polaris-oid4vp; the verifier's certificate was self-signed and trusted on the phone through
developer mode.

The phone ran iOS with the Yivi app 8.3.1 from the App Store, in developer mode. The credential was
Yivi's email credential (`vct` `pbdf.sidn-pbdf.email`), issued to the app by Yivi. The verifier
was `polaris-oid4vp` from this tree, unchanged, behind a Cloudflare quick tunnel on a Mac. It
accepted the presentation (`200`, authentic) and refused both negatives.

The email credential shows that the presenter controlled the mailbox when the credential was
issued. It does not show current enrolment or employment at that domain.

This is not a production claim. The phone trusted the verifier only because its root was added by
hand under developer mode. A verifier that the store app trusts as shipped needs a Yivi Trusted
Verifier certificate, issued under Yivi's Relying Parties CA. This walk did not use one.

## What was asked, and what came back

The request asked for exactly one claim: DCQL, one `dc+sd-jwt` credential query, `vct_values`
`["pbdf.sidn-pbdf.email"]`, claim path `["domain"]`, with no value filter. The signed request
object is [`live-2026-10-14/request-object.jwt`](live-2026-10-14/request-object.jwt): ES256,
`typ` `oauth-authz-req+jwt`, an `x509_hash` client_id, `response_mode` `direct_post.jwt`, with a
lifetime of 300 s.

| | |
|---|---|
| Live verdict | `200`, authentic, under the issuer trust list below |
| Selectively disclosed | exactly one claim, `domain` = `<the presenter's email domain, withheld>` |
| Always-visible JWT fields | `iss` = `https://is.yivi.app`, `vct` = `pbdf.sidn-pbdf.email`, `iat`, `exp`, `cnf` (the holder key; not published) |
| Issuer `x5c` | one certificate: the leaf `CN=is.yivi.app,O=Yivi,C=NL` (CA false, EKU `1.3.6.1.5.5.7.3.2`, KU digitalSignature, SAN `https://is.yivi.app` and `is.yivi.app`), DER SHA-256 `61914abef02f8ce22a46c79da3a442f13db739b374e2f955c9bb120a050c2870` |
| The chain reached | `CN=Yivi Attestation Providers CA,O=Yivi,C=NL`. The leaf is signed by it, not by the Root, and the x5c carries no anchor and no self-signed certificate |

The credential's own `_sd` list held two digests: one for the disclosed `domain`, and one not
disclosed (by the credential type, the address itself). The app disclosed `domain` only. The domain is withheld here as well: it identifies the presenter's organisation.
[`live-2026-10-14/result.json`](live-2026-10-14/result.json) holds these facts. Nothing in this
directory holds the vp_token, the posted JWE, a disclosure, the key binding JWT, the holder key or
an `_sd` digest. Those stay in a private capture outside the repository.

## Issuer trust

Yivi publishes two issuer anchors in irmago v1.4.1 `eudi/trustanchors.go`
(`Production_Yivi_IssuerTrustAnchor`; the file's SHA-256 is
`07d6bc671d4b8bd464f810e1efc47930375b8ca4418965f6d9439fb9f09f00c9`). They were fetched by
anonymous curl and are pinned here by the SHA-256 of their DER:

| File | Subject | DER SHA-256 |
|---|---|---|
| [`yivi-attestation-providers-ca.pem`](yivi-attestation-providers-ca.pem) | `CN=Yivi Attestation Providers CA,O=Yivi,C=NL` | `0c7e79d26737cda146e77bad55f96153604a1445cb5b3417f8ca3b4b9a8cc1bf` |
| [`yivi-requestors-root-ca.pem`](yivi-requestors-root-ca.pem) | `CN=Yivi Requestors Root CA,O=Yivi,C=NL` | `7a1576244da5a552df90f27cd4a9d944f6a0d3855a43865f1b195767ef4c1e69` |

The live run trusted both, which is irmago's own pair. `walk.sh` trusts the Attestation Providers
CA alone. The Requestors Root also certifies Yivi's Relying Parties CA, so trusting it as an issuer
anchor could let a certificate made for a relying party pass as an issuer's whenever its usages
permit signing. The live
presentation was judged again offline with `polaris-oid4vp verdict --now <the instant it
arrived>`:

| Trust list | Verdict |
|---|---|
| Attestation Providers CA alone (what `walk.sh` trusts) | accepted |
| Both anchors (the live run; irmago's pair) | accepted |
| Requestors Root alone | refused, `issuer_key`: the x5c leaf does not chain to any configured trust anchor |
| An unrelated root, negative (b) | refused, `issuer_key`: the x5c leaf does not chain to any configured trust anchor |

`polaris-oid4vp` refuses an `x5c` that carries a configured anchor or a self-signed certificate
(HAIP 1.0 section 6.1.1). The chain's shape
was unknown before the scan. The real chain is the leaf alone, so neither rule applied,
and the strict and adjusted trust lists (the pair minus any anchor the chain carries) were the
same.

## Negatives

- **(a) Replay.** The captured response was posted again to the live verifier and refused with
  `400 invalid_request`: "the response did not decrypt under any outstanding request's key: it was
  encrypted to somebody else, altered, or it answers a request that has expired". An answered
  request is closed, and its key goes with it.
- **(b) Issuer trust.** The captured presentation was refused offline at the recorded instant under
  an unrelated root: `issuer_key`, "the x5c leaf does not chain to any configured trust anchor".
  The Requestors Root alone was refused with the same code, but only because Yivi's x5c carries the
  leaf without the Attestation Providers CA: a chain sent with its intermediate would be accepted
  under the Root alone, a relying party's included (`IssuerAnchorScopeTests` in polaris-oid4vp). The Attestation Providers CA alone
  accepts the same presentation, so the anchor is the only thing that changed between the two.

## The tunnel was public

The Cloudflare quick tunnel (no account; the verifier's keys were test keys) put the local
verifier on a public `trycloudflare.com` URL for the length of the run. Everything
`polaris-oid4vp serve` answers was reachable there (`serve.py`):

- `GET /request.jwt?state=...`: the signed request object of an outstanding request, and `404`
  otherwise;
- `POST /request.jwt`: the same, for `request_uri_method=post`, with a wallet nonce;
- `POST /response`: the response endpoint;
- `GET /done`: the page an accepted wallet is redirected to, for the redirect's own `response_code`
  and only once, and `404` otherwise;
- every other path: `404` to GET and POST. Other methods get the standard library's `501`.

In the live run, cloudflared started at 03:36:35Z and stopped at 03:39:31Z on 2026-10-14 (from its
own log). It was then torn down by its recorded PID, as was the verifier. The presentation
crossed the tunnel as `direct_post.jwt`, encrypted (ECDH-ES, A128GCM) to a key made for that one
request. Cloudflare, which terminates the public TLS, carried ciphertext.

## Files

- [`live-2026-10-14/`](live-2026-10-14/): what ran, and its public facts. [`live.sh`](live-2026-10-14/live.sh)
  and [`live.py`](live-2026-10-14/live.py) are the runner of the live scan, with only their paths
  made parameters. `live.sh` started the quick tunnel (HOME a fresh temporary directory) and
  `polaris-oid4vp serve --once` unchanged, with the two anchors, `--vct pbdf.sidn-pbdf.email
  --claim domain`. It waited for the tunnel, then opened the QR code of the
  `https://open.yivi.app/-/openid4vp?...` link, and returned. `live.py` wraps the verifier so that
  the posted form and its decryption are written to the private capture before the verifier judges
  them. The replay and the offline verdicts were run by hand after the scan.
- [`walk.sh`](walk.sh) and [`walk.py`](walk.py): the reproducible runner for re-runs. It does all of
  the above in one command, trusts the Attestation Providers CA alone, runs the replay and the
  offline set, tears down by recorded PIDs, and prints `walk.sh: done` only when the presentation
  was accepted and every negative refused.
- [`standin_wallet.py`](standin_wallet.py): the rehearsal's wallet, used in place of the phone.
- [`public_guard.py`](public_guard.py) and [`test_public_capture.py`](test_public_capture.py): what
  may not be published, and the test that holds every directory here with a `result.json` to it.

## Run it again

    lab/interop/yivi/walk.sh              # the walk: a QR code for the phone
    lab/interop/yivi/walk.sh --rehearse   # a rehearsal: a stand-in wallet, no phone

It needs `cloudflared`, `qrencode` and `openssl`, the test venv (`POLARIS_PY`), and the verifier
PKI at `~/Desktop/polaris-private/captures/yivi/pki/` (`YIVI_PKI`). The PKI is made once, by hand
(`polaris-oid4vp keygen --out <dir> --host <name>`), and only read here. Its `anchor.pem` is the
root on the phone. The same PKI keeps the same `x509_hash` client_id, so the root stays valid
across runs. keygen makes the leaf valid for 90 days: the live PKI's leaf expires on about
2027-01-12, and `walk.sh` then refuses to start. A run after that date needs a new PKI, and the
new root added on the phone again. Public facts go to `capture/<stamp>/`, and holder data to
`~/Desktop/polaris-private/captures/yivi/runs/<stamp>/`.

On the phone, once: Developer mode (More, tap the version line 7 times), then More, Debugging,
Certificate management, +, choose Verifier, paste `anchor.pem`, Add. The type selector starts at
Issuer; check it still reads Verifier before tapping Add.

## Rehearsal, 2026-10-14 (a stand-in wallet, not the Yivi app)

`walk.sh --rehearse` ran end to end through a real quick tunnel, with
[`standin_wallet.py`](standin_wallet.py) in place of the phone. It fetches the request object by
GET, checks its signature and `x509_hash`, presents an SD-JWT VC of the same `vct` with the
`domain` disclosure only, and posts it encrypted. The stand-in's issuer CA was added to the trust
list for that run only. It took 83 s, most of it waiting for the new tunnel name to resolve. The
public files are in [`rehearsal/`](rehearsal/). The run's output, links omitted:

    walk.sh: tunnel origin https://bibliographic-portland-church-consequence.trycloudflare.com
    walk: the tunnel answers: GET https://bibliographic-portland-church-consequence.trycloudflare.com/done -> 200
    walk: request started at 2026-10-14T03:54:52Z; it expires at 2026-10-14T03:59:52Z (300 s)
    walk: request object fetched (GET), served=True
    walk: post0: <- 200 authentic
    walk:   stand-in: fetched the request object by GET: bibliographic-portland-church-consequence.trycloudflare.com (2292 bytes)
    walk:   stand-in: posted the encrypted response to bibliographic-portland-church-consequence.trycloudflare.com: 200 {"redirect_uri": ".../done"}
    walk: negative (a), the response replayed: <- 400 invalid_request: the response did not decrypt under any outstanding request's key: ...
    walk: offline configured: accepted=True
    walk: offline root_only: accepted=False issuer_key: the x5c leaf does not chain to any configured trust anchor
    walk: offline unrelated_root: accepted=False issuer_key: the x5c leaf does not chain to any configured trust anchor
    walk: offline irmago_pair: accepted=False issuer_key: the x5c leaf does not chain to any configured trust anchor
    walk: public files checked: no disclosure, SD-JWT, KB-JWT, holder key, _sd list, email, or the 1 disclosed value(s)
    walk.sh: the tunnel (pid 8828) is stopped
    walk.sh: done

`irmago_pair` refuses in the rehearsal because the stand-in's credential chains to the stand-in CA,
not to Yivi's.

## What this does not establish

- One phone, one app build, one credential type, one claim, one run. It is not a claim of
  interoperability in general.
- It is not production trust: the root was added by hand in developer mode (see above).
- No revocation status was read. The credential carried no `status` claim, and the verdict reports
  revocation as not evaluated.
- The phone's own checks are irmago's (lab/interop/irmago tests the library against this verifier).
  This walk adds the store app, its trust store and its user interface.
- The author drove both ends. It is not an outside party using Polaris.
