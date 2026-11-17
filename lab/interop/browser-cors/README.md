# browser-cors: a browser reads `serve --cors-origin` across origins

[`witness.py`](witness.py) is the second witness to the package's CORS tests: it hands the
decision to a browser's own CORS check rather than to a reading of the Fetch Standard. Headless
Chromium loads a page from one 127.0.0.1 port and, from that page's script, reads a
`polaris-oid4vp` listener on another:

| Read | Path | What a wallet page does |
|---|---|---|
| request object | `GET /request.jwt?state=...` | fetches the signed request object |
| unknown state | `GET /request.jwt?state=no-such-state` | reads a 404 |
| form response, no preflight | `POST /response`, `application/x-www-form-urlencoded` | posts its response; reads the 400 |
| JSON response, preflighted | `POST /response`, `application/json` | the browser sends `OPTIONS` first |

Each read is made three ways: from the page origin on the listener's `--cors-origin` list (every
read succeeds), from another port (every read fails as a network error), and against a listener
without the option (every read fails). A dead port fails a read with the same `TypeError` as a
browser's CORS refusal, so before a column's reads count, a `no-cors` GET to its listener must
resolve; a column whose listener answers nothing is `BAD`. Any live server without CORS headers
fails the reads too, so the column of the listener without the option also needs it to be a
`polaris-oid4vp` listener: an unknown state, asked from the witness's own process with the page's
`Origin`, must get the 404 JSON `not_found` with no `Access-Control-Allow-Origin`, or the column is
`BAD`. Chromium's URL parser also writes each kept row of the package's origin table (`CORS_KEPT` in
`packages/polaris-oid4vp/test_serve.py`), which must equal what `cors_origin` keeps.

## Run it

    python3 witness.py tree
    python3 witness.py url http://127.0.0.1:9443 --state STATE --page-port 8765 --from WHAT \
        [--without URL --without-from WHAT]

`tree` starts both listeners in the process, from this checkout's `packages/polaris-oid4vp`. `url`
reads a listener already running, started with
`--cors-origin http://127.0.0.1:8765`; `serve --once` prints the `state` of the request it issues.
`--from` and `--without-from` name what each listener was started from, such as its image digest,
and end every result line of the column that reads it. It needs Playwright's Chromium
(`pip install playwright && playwright install chromium`). It prints Chromium's version and one line
per read, then `done`, and exits 1 when a read or a row is not what its column says.

## Results

2026-11-17, Chromium 153.0.8010.12 (Playwright 1.63.0), Python 3.12.13.

`tree`: the four reads succeed from the listed origin (200 `application/oauth-authz-req+jwt`, 404,
400, 400); all eight from the unlisted origin and against the listener without the option fail
with `TypeError: Failed to fetch`; Chromium writes 21 of 21 kept origins as the package keeps
them. Its control, the listed pass pointed at the listener without the option, reads `BAD` four
times and exits 1.

`url`, against listeners started with this tree's `serve --no-local-tls`, one with `--cors-origin`
for the page's port and `--once`, one without the option, each line ending with its `--from` or
`--without-from` label:

| Run | What it printed | Exit |
|---|---|---|
| `--without` the listener without the option | the same twelve reads, `done` | 0 |
| `--without` a port nothing listens on | `off  a no-cors GET  BAD  nothing answered` | 1 |
| the base at a port nothing listens on | `listed` and `unlisted`: `a no-cors GET  BAD  nothing answered` | 1 |
| `--without` a `python -m http.server` | `off  an unknown state  BAD  not a polaris-oid4vp listener without the option` | 1 |
| `--without` with no `--without-from` | the `url` usage and `--without needs --without-from` | 2 |

Each guard taken out of a copy, the same runs: without the identity read, the run against
`python -m http.server` prints `ok` four times in the off column and `done`, exit 0. Without the
`no-cors` GET, the run at a dead `--without` is still refused, by the identity read; with the base
at a dead port, the unlisted column prints `ok` four times while the listed column reads `BAD`
four times, exit 1.
