# site/: the published project page and the images the repository shares

**Reader:** anyone editing the public page at
[polaris-id.e-khaklin.workers.dev](https://polaris-id.e-khaklin.workers.dev/),
or looking for the logo.
**Job:** hold one copy of each published artifact, so the page and the README
can never disagree about what Polaris looks like.

Cloudflare publishes this directory on every push to main (`wrangler.jsonc` at
the root of the repository). Nothing here is generated at build time: what is
committed is what is served, so opening `index.html` from a clone shows the same
page a visitor sees. The old address, egorkhaklin.github.io/polaris-id, redirects
here (`.github/workflows/pages.yml`, which also re-checks the page's numbers and
links on every push).

`_headers` is the site's security policy, in Cloudflare's `_headers` format
(GitHub Pages cannot send response headers). The policy allows styles,
images and fonts from the site itself and nothing else: no inline style or script, no
other origin, no framing. `check_site_pages_render_under_their_headers` reads
the policy and every page and stylesheet here, so a page that would render
broken under it fails the build.

## What is here

| File | What it is | Read by |
|---|---|---|
| `index.html` | The whole page: markup and content. It runs no script: the hero's turning star trails are CSS, and stop under `prefers-reduced-motion` | The published site |
| `index.css` | The page's styles, outside the page so the policy can refuse inline style | `index.html` |
| `tokens.css` | The design tokens, under the same names `polaris_web/static/polaris.css` uses | `index.html`, `404.html` |
| `404.html`, `404.css` | The not-found page and its styles | The host, for any unknown path (`not_found_handling` in `wrangler.jsonc`) |
| `_headers` | The security headers the host sends with every file | Cloudflare |
| `robots.txt` | Crawl policy: one page, nothing private | Crawlers |
| `llms.txt` | The project for a reading agent: what it is and is not, the one-minute offline check with its exit codes, and where the specifications and evidence live, as absolute links | Agents and tools that read `/llms.txt` |
| `favicon.svg` | The tab icon | `index.html`, `404.html` |
| `og.png` | The 1200 x 630 social card: the emblem, the page's headline, "pre-pilot" and the maker's mark, captured from the page's own styles | `index.html` (`og:image`) |
| `khaklin.svg` | The KHAKLIN TECHNOLOGIES lockup in the site's gold, from the traced lettering and owl (never redrawn) | `index.html` (footer), `og.png` |
| `fonts/` | Inter, Cinzel and JetBrains Mono: the console's own files from `polaris_web/static/vendor/fonts/`, byte for byte, each beside its SIL OFL licence | `index.css`, `404.css` |
| `polaris_logo_clean.png` | The emblem, 440 x 440, unchanged; drawn at 28 to 220 CSS pixels | `index.html`, the Open Graph preview, `docs/assets/hero.svg` (embedded), the Helm chart icon |
| `openid-certified-mark-on-white.png` | The OpenID Certified mark, shown beside the scoped certification statement | `index.html` |

## Conventions

- One copy of every binary, with two exceptions, each byte for byte, because the
  site can serve only this directory: the OpenID Certified mark is also in
  `docs/assets/` (the published polaris-oid4vp README links to that path), and
  `fonts/` repeats the console's vendored fonts.
- Outbound links to repository documents are absolute `github.com/.../blob/main`
  URLs. A relative link would 404 on the published site, whose root is this
  directory.
