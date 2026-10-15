# Check in with the Yivi app

A door check-in built on polaris-oid4vp's public `Verifier`. The desk shows a QR code. The Yivi app
presents its email credential with one claim disclosed, `domain`. If that domain is on the
allow-list, the desk shows "Checked in" and the domain. Otherwise it shows "Not checked in" and
the reason. [`app.py`](app.py) is the whole app.

This runs in developer mode, not production. The phone trusts this verifier only because its root
was added by hand in the Yivi app's developer mode. For the store app to trust a verifier as
shipped, the verifier needs a Yivi Trusted Verifier certificate, which comes from registering with
Yivi.

## Run it

1. With Python 3.11 or newer (the pinned starlette needs it), from this directory, install the
   app's requirements, then polaris-oid4vp from this checkout:
   `python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements.txt && .venv/bin/pip install ../..`
2. Make the verifier's keys, once: `.venv/bin/polaris-oid4vp keygen --out pki --host localhost`.
3. On the phone, once:
   - Turn on developer mode: More, then tap the version line seven times.
   - Add the verifier's root: More, Debugging, Certificate management, +.
   - Choose Verifier. The type selector starts at Issuer, so check it says Verifier.
   - Paste the contents of `pki/anchor.pem` and tap Add.
4. Open a tunnel to the laptop: `cloudflared tunnel --url http://127.0.0.1:8000`. It needs no
   account. It prints a `https://….trycloudflare.com` address.
5. Start the app with that address and your domains, then open http://127.0.0.1:8000/ on the
   laptop and scan the QR code:
   `CHECKIN_PUBLIC_URL=https://….trycloudflare.com CHECKIN_PKI=pki CHECKIN_ALLOWED=example.edu .venv/bin/python app.py`

`CHECKIN_ISSUER_CA` sets which issuer CA is trusted. It defaults to
[`yivi-attestation-providers-ca.pem`](yivi-attestation-providers-ca.pem), the Yivi Attestation
Providers CA. This is the same file [lab/interop/yivi](../../../../lab/interop/yivi/README.md)
pins (DER SHA-256 `0c7e79d2…`). The default is that CA and not Yivi's Requestors Root, because
the Requestors Root also certifies relying parties.

`CHECKIN_ISSUER` sets the one issuer accepted under that CA. It defaults to Yivi's own,
`https://is.yivi.app`. The CA certifies every Yivi attestation provider, and any of them can sign
this credential type.

`CHECKIN_EVENT` puts an event name over the headline, for example `Technology Club`.
`CHECKIN_LOGO` sets the emblem on the desk. It defaults to the project site's,
`site/polaris_logo.webp`, and the desk shows no emblem when that file is absent. The desk uses the
site's colours, from `site/tokens.css`.

## What is checked

- polaris-oid4vp judges the presentation:
  - a signed request with an `x509_hash` client_id;
  - a response encrypted to that one request;
  - the issuer's `x5c` chaining to the trusted CA;
  - a key binding to this request's nonce;
  - exactly `domain` disclosed.
- The app then checks the issuer: the verdict's `iss_bound` must be `True` and its `claims["iss"]`
  must be `CHECKIN_ISSUER`. polaris-oid4vp refuses a leaf that names another issuer. When the
  leaf names no issuer, it leaves the `iss` out of `claims`. A common name does not count as
  naming an issuer.
- The app then compares the domain with `CHECKIN_ALLOWED`. The match ignores ASCII case and must
  be exact: a subdomain does not match, and a domain with any non-ASCII character is refused.
  Write an internationalized domain in its `xn--` form.
- Off the list, the wallet gets the verifier's usual refusal, and the desk shows the domain and
  that it is not on the list.
- The desk pages, and the emblem they show, answer only on the laptop, checked by the loopback
  address and the `Host` header. Through the tunnel, only the wallet's paths answer: `/request/<id>` and `/response/<id>`.
  An accepted wallet gets no redirect: the desk shows the result.
- Someone who sees the QR code can post to `/response/<id>`. If that post does not decrypt under
  the request's key, it changes nothing: the request stays open and the desk keeps waiting. A
  post after the request has closed, answered or expired, changes nothing either.

## What it shows and keeps

The desk shows the domain and nothing else from the credential. It receives more than it shows:
besides the disclosed domain, a presentation carries the credential's always-visible claims, which
are its issuer (`iss`), type (`vct`) and dates (`iat`, `exp`), and `cnf`, a key from the phone that
is the same at every presentation of that credential. The email address itself is never sent. The
credential shows that the holder controlled an address at that domain when the credential was
issued. It does not show current enrolment or membership. A check-in shows that someone answered
this QR code with such a credential, not that it was the person at the desk: anyone who sees the
code can answer it first.

Nothing is written to disk. An outcome stays in memory for the request's lifetime (300 s) plus a
minute. The example keeps no access log; an operator who adds one keeps attendees' IP addresses.
The tunnel is not part of the example: Cloudflare, which carries each request, sees the attendee's
IP address under its own terms.

## Test

`CHECKIN_REQUIRED=1 python -m unittest test_checkin` runs the app on a local port and scans it
with the Yivi walk's stand-in wallet ([`standin_wallet.py`](../../../../lab/interop/yivi/standin_wallet.py)).
It covers these cases:

- an allowed domain is checked in;
- a domain off the list is refused;
- an untrusted issuer is refused;
- another provider under the same CA is refused, whether it signs as itself or claims the
  expected issuer;
- a leaf that names no issuer, or names it only in its common name, is refused;
- a post that does not decrypt changes nothing, and neither does one after the check-in or after
  the request expired;
- a domain that matches the list only after non-ASCII case folding is refused;
- a wallet's error response (the holder declined) changes nothing;
- the desk is not served through the tunnel;
- `python app.py` keeps no access log: its output through a scan holds no client address.

CI runs it in a separate job step that installs `requirements.txt`. Without `CHECKIN_REQUIRED`,
the suite is skipped when those requirements are missing.

The waiting page shows a QR code and refreshes itself, as the Yivi web frontend's flow does (yivi-frontend-packages).
