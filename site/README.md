# site/: the published project page and the images the repository shares

**Reader:** anyone editing the public page at
[polaris-id.org](https://polaris-id.org/),
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
| `index.html` | The whole page: a hero, then eight acts (the check, evidence, how it works, the rules, the hard cases, why now, mission, work with us). It runs no script: the hero's sky turns, the coin settles as the page loads and tilts toward the pointer, and the acts are drawn as they scroll into view (some acts only on larger screens), all in CSS; everything holds still under `prefers-reduced-motion` | The published site |
| `index.css` | The page's frame and the hero: the turning sky, and the coin's poses, rim and shadow (those rules are generated with the coin's renders), outside the page so the policy can refuse inline style | `index.html` |
| `film.css` | The eight acts: their layout and still state, and the motion that draws them as they scroll, which runs only where the browser has scroll-driven animations and the reader has not asked for reduced motion | `index.html` |
| `tokens.css` | The design tokens, under the same names `polaris_web/static/polaris.css` uses | `index.html`, `404.html` |
| `404.html`, `404.css` | The not-found page and its styles: the coin at rest, with its shadow | The host, for any unknown path (`not_found_handling` in `wrangler.jsonc`) |
| `_headers` | The security headers the host sends with every file | Cloudflare |
| `robots.txt` | Crawl policy: one page, nothing private | Crawlers |
| `llms.txt` | The project for a reading agent: what it is and is not, the one-minute offline check with its exit codes, and where the specifications and evidence live, as absolute links | Agents and tools that read `/llms.txt` |
| `og.png` | The 1200 x 630 social card: the coin as the page shows it at rest, with the shadow it casts, at the still centre of the night's star trails (computed from the Yale Bright Star Catalogue, so the card holds only the project's own work), the page's eyebrow and headline, and the maker's mark | `index.html` (`og:image`) |
| `khaklin.svg` | The KHAKLIN TECHNOLOGIES lockup in the site's gold, from the traced lettering and owl (never redrawn) | `og.png` (the maker's mark) |
| `fonts/<face>.<hash>.woff2` | Inter, Cinzel and JetBrains Mono: the console's own files from `polaris_web/static/vendor/fonts/`, cut to the Latin characters a page can need and the ones this site uses, with every glyph outline, OpenType feature, variation axis and name record kept, each beside its SIL OFL licence (none reserves a font name) | `index.css`, `404.css` |
| `polaris_logo.webp` | The emblem, rendered from an exact model of its geometry (gold relief with chiselled rays over blue enamel), 880 x 880, transparent outside its disc | `docs/assets/hero.svg` (embedded byte for byte), the desk of the Yivi check-in example (`packages/polaris-oid4vp/examples/yivi-checkin`) |
| `polaris_logo_180.png` | The same emblem at 180 x 180, framed as `polaris_logo.webp` is | `index.html`, `404.html` (the tab and home-screen icons) |
| `polaris_logo_clean.png` | The emblem as first published, 440 x 440 | The Helm chart's icon (`deploy/helm/polaris/Chart.yaml`) |
| `hero/coin-<pose>-384.<hash>.avif`, `-640` | The coin: the emblem as a gold and enamel medallion, path-traced in Blender from the same model, each pose seen straight on. Poses 0 to 8 answer the nine parts of the coin a pointer can rest on (4, the centre, is the coin at rest); `rx13`, `rx23` and `rx28` are the coin tipped back as the page carries it up. `coin-4-640.<hash>.webp` is the rest pose for browsers without AVIF | `index.html`, `index.css`, `404.html` |
| `hero/coin-shadow-dir.<hash>.avif`, `hero/coin-shadow-ao.<hash>.avif` | The coin's shadow on the sky, path-traced in two layers: the lamp's, and the room's | `index.html`, `404.html` |
| `hero/sky-1600.<hash>.avif`, `-2400`, `-3200`; `hero/sky-2400.<hash>.webp` | The real sky round the north celestial pole for October 2026, on black, which the page screen-blends: the naked-eye stars (Yale Bright Star Catalogue, 5th edition, to magnitude 6.5) and the Milky Way of NASA's Deep Star Maps 2020 (credit: NASA/Goddard Space Flight Center Scientific Visualization Studio; Gaia DR2: ESA/Gaia/DPAC), out to 54 degrees in a stereographic view; licensed CC BY-SA 3.0 IGO (`REUSE.toml`). The WebP is for browsers without AVIF | `index.html` (the hero) |
| `film/iii-<object>-540.<hash>.avif`, `-1080` | Act III's objects, path-traced under the coin's lamp: a steel die (`die`), a written page (`paper`) and the Cardan grille laid over it (`grille`), a printed table of keys (`table`) and a loupe (`loupe`) | `index.html` |
| `film/iv-wall-<light>-1600x1000.<hash>.avif`, `-900x1400` | Act IV's polished black marble wall, path-traced once under each of its two lights: a raking light from the right (`rake`) and the coin's lamp (`lamp`). The narrow pair is for phones | `index.html` |
| `film/vii-sheet-1x.<hash>.avif`, `-2x` | Act VII's twelve frames, three by four on one sheet: a stack of blank cards and papers sliding together into one unstruck gold blank | `index.html` |
| `film/trails-30m-<width>.<hash>.avif` | Half an hour of the northern sky's star trails round the pole: the stars of the Yale Bright Star Catalogue over the hero's Milky Way, turned together; licensed as the hero's sky is (`REUSE.toml`). The page lays four copies, each turned a further half hour, into the two-hour exposure behind the last act | `index.html` |
| `openid-certified-mark-on-white.png` | The OpenID Certified mark in the Foundation's published form: the first proof tile, linked to the listing | `index.html` |

## Conventions

- One copy of every binary, with one exception, byte for byte, because the
  site can serve only this directory: the OpenID Certified mark is also in
  `docs/assets/` (the published polaris-oid4vp README links to that path).
  `fonts/` holds cuts of the console's vendored fonts, not copies.
- Outbound links to repository documents are absolute `github.com/.../blob/main`
  URLs. A relative link would 404 on the published site, whose root is this
  directory.
