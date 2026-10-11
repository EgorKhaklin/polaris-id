# response-uri-statuses: what polaris-oid4vp's Response URI answers

[`measure.py`](measure.py) posts one request per kind of response to `/response`, the Response URI
`polaris-oid4vp serve` listens on, through serve.py's own request handler over an in-memory socket (no
port, no network), and prints the HTTP status, content type and verdict of each. OpenID4VP 1.0 section
8.2 fixes one of them: a Response URI that "has successfully processed the Authorization Response or
Authorization Error Response" answers 200, `application/json` and a JSON object.

What it posts, in order:

| Group | Requests |
|---|---|
| vectors | each presentation in [`../negative-vectors/vectors.json`](../negative-vectors/vectors.json), encrypted to a live request's key and posted as `response=<JWE>`, as a wallet using `direct_post.jwt` sends it |
| extra | 11 failures the vectors do not carry, made with their generator: an issuer signature with one byte flipped; a key binding JWT for another nonce, audience or instant; an expired credential; another `vct`; a requested claim withheld; an unrequested one disclosed; a status list that says INVALID, and one that does not answer; a string that is no presentation |
| response | 13: an empty POST; an unencrypted `vp_token`; an Authorization Error Response in the clear (`error=access_denied&state=...`) and encrypted (`{"error", "state"}` in the JWE); a `response` that is not a JWE; one encrypted to another request's key; a `state` that is not its key's request; a `vp_token` missing, under another id, or holding two; a replay; an expired request |
| transport | 4: a `Content-Length` that is not a number; a body over 1 MiB; an unknown path; a verifier that raises |

The verifier judges at the vectors' instant and expects their audience and nonce; nothing else about
the decision is changed. The run fails, without printing `done`, when the vectors file holds no vectors
or when a control is not accepted: the vectors' two, and the generator's own presentation (the first
replay POST), which the extra classes are made from.

## Run it

    python3 measure.py tree                      # this checkout's packages/polaris-oid4vp
    python3 measure.py installed                 # the polaris-oid4vp this Python imports
    python3 measure.py tree --vectors FILE --json results.json

It needs `cryptography`. `--vectors` takes another vectors file with the same settings, such as
version 0.1.0 (23 vectors): `git show dbc708a8:lab/interop/negative-vectors/vectors.json`.

## Results

2026-10-11, Python 3.12.13: 1.0.0rc18 installed from PyPI (cryptography 50.0.2) and this tree,
1.0.0rc20 (cryptography 50.0.1).

| Response | 1.0.0rc18 | this tree |
|---|---|---|
| a valid presentation: the two controls, the first replay POST | 200, only `redirect_uri` | the same |
| a status list that does not answer | 200, only `redirect_uri` | the same |
| every other presentation and response above, and a verifier that raises | 400, one constant body | the same |
| a `Content-Length` that is not a number; over 1 MiB; an unknown path | 400; 413; 404 | the same |
| an Authorization Error Response, in the clear or encrypted | 400, the constant body | 200, `{}` |

With this tree's vectors (0.2.0, 25), 53 requests: 1.0.0rc18 `200 x4, 400 x47, 404 x1, 413 x1`, this
tree `200 x6, 400 x45, 404 x1, 413 x1`. With vectors 0.1.0, 51 requests: `200 x4, 400 x45, 404 x1,
413 x1` and `200 x6, 400 x43, 404 x1, 413 x1`. Either way the two error responses are the only
requests whose status, content type, body or verdict code differ.
