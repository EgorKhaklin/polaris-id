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
images, fonts, scripts and the web manifest from the site itself and nothing else: no inline
style or script, no other origin, no framing. `check_site_pages_render_under_their_headers` reads
the policy and every page and stylesheet here, so a page that would render
broken under it fails the build.

## What is here

| File | What it is | Read by |
|---|---|---|
| `index.html` | The landing page: the Polaris card reference design (PC-0001), a render that rises into place and shows its surface or its inside under a lens, from the front, the back and close up; a band where the card comes apart into its layers; then why now, what Polaris does (the OpenID Certified mark, linked to the Foundation's listing with the certified package named in its text alternative, and the projects it was tested with), what it is built for and how a check works. Its three scripts are served from the site itself and the page reads complete without them; under `prefers-reduced-motion` the opening screen is skipped and the motion holds still | The published site |
| `bp.css` | The landing and contact pages' styles: the layout for each window size, the type, the card's stage and the drawing sheets, with the fonts' `@font-face` rules; outside the pages so the policy can refuse inline style | `index.html`, `contact.html` |
| `pre.js`, `bp.js` | The landing page's own scripts. `pre.js` runs before first paint and shows the opening screen once per visit, by a mark in the browser's session storage; `bp.js` is the motion: the card's frames, the lens, the band that opens the card, and the words that rise into place | `index.html` |
| `vendor/lenis-1.3.27.min.js`, `vendor/lenis-LICENSE.txt` | Lenis 1.3.27, the smooth-scroll library, served from this site, beside its MIT licence | `index.html` |
| `contact.html`, `contact.css`, `contact.js` | The contact page: a form whose button opens a draft in the visitor's own mail app; the page itself sends nothing | The published site, at `/contact` |
| `card/hero-still-<width>.webp`, `card/xray-still-<width>.webp`, `card/view-<view>-<kind>-<width>.webp`, `card/exploded-still-<width>.webp` | The Polaris card reference design, path-traced in Blender: the card at rest and the same card with its body turned to glass, from the front, the back (`back`) and close up (`macro`), and the card opened into its layers; each 1600, 2560 and 3840 pixels wide | `index.html` |
| `card/arrive/f-<n>.webp`, `card/explode/f-<n>.webp` | The frames of the card rising into place (30) and coming apart (32) | `bp.js` |
| `card/bp-<sheet>-print.webp`, `card/bp-exploded-dark.webp` | The card's drawing sheets: the back, the plate, the exploded view and the section | `index.html` |
| `mark.webp` | The site's mark beside its name: the emblem's sun in gold, 512 x 512, transparent around it | `index.html`, `contact.html` |
| `favicon.ico`, `icon-48.png`, `icon-96.png`, `icon-180.png`, `icon-192.png`, `icon-512.png` | The site icon: the emblem's sun in gold on a black square, 16, 32 and 48 in the icon file | Every page (the tab icon; 180 is the home-screen icon of `index.html` and `contact.html`), `site.webmanifest` (192 and 512), the landing page's structured data (512), and any client that asks for `/favicon.ico` |
| `site.webmanifest` | The web manifest: the site's name, its icons and its colours | `index.html` |
| `grain.png` | A film grain laid over the page, 220 x 220 | `bp.css` |
| `vercel.json` | The `_headers` policy and clean addresses in Vercel's format, for a build served there | Vercel |
| `index.css` | The page's frame and the hero: the turning sky, and the coin's poses, rim and shadow (those rules are generated with the coin's renders), outside the page so the policy can refuse inline style | Kept at its address; no page here loads it since the 2026-11-25 rebuild |
| `film.css` | The six acts and the night: their layout and still state, and the motion that draws them as they scroll, which runs only where the browser has scroll-driven animations and the reader has not asked for reduced motion | Kept at its address; no page here loads it since the 2026-11-25 rebuild |
| `tokens.css` | The design tokens, under the same names `polaris_web/static/polaris.css` uses | `index.html`, `contact.html`, `404.html`, `privacy.html` |
| `404.html`, `404.css` | The not-found page and its styles: the coin at rest, with its shadow | The host, for any unknown path (`not_found_handling` in `wrangler.jsonc`) |
| `privacy.html`, `privacy.css` | The privacy notice of Khaklin Technologies LLC, which builds Polaris ID, and its styles | The published site, at `/privacy` |
| `_headers` | The security headers the host sends with every file | Cloudflare |
| `robots.txt` | Crawl policy: nothing private, and where the sitemap is | Crawlers |
| `sitemap.xml` | The site's three pages, `/`, `/privacy` and `/contact`, for search engines | Crawlers, through `robots.txt` |
| `llms.txt` | The project for a reading agent: what it is, the one-minute offline check with its exit codes, and where the specifications and evidence live, as absolute links | Agents and tools that read `/llms.txt` |
| `og.png` | The 1200 x 630 link card: the Polaris card reference design at rest, the site's mark and name, the page's headline and the card's drawing number | `index.html` (`og:image`, `twitter:image`) |
| `khaklin.svg` | The KHAKLIN TECHNOLOGIES lockup in the site's gold, from the traced lettering and owl (never redrawn) | `index.html` (the opening screen and the footer), `contact.html` (the footer) |
| `fonts/<face>.<hash>.woff2` | Inter, Cinzel and JetBrains Mono: the console's own files from `polaris_web/static/vendor/fonts/`, cut to the Latin characters a page can need and the ones this site uses, with every glyph outline, OpenType feature, variation axis and name record kept, each beside its SIL OFL licence (none reserves a font name) | `bp.css`, `404.css`, `privacy.css` |
| `polaris_logo.webp` | The emblem, rendered from an exact model of its geometry (gold relief with chiselled rays over blue enamel), 880 x 880, transparent outside its disc | `docs/assets/hero.svg` (embedded byte for byte), the desk of the Yivi check-in example (`packages/polaris-oid4vp/examples/yivi-checkin`) |
| `polaris_logo_180.png`, `polaris_logo_192.png` | The coin, path-traced as the not-found page's is but untilted, cut to its disc so the disc fills the square: 180 x 180 and 192 x 192 | Kept at its address; no page here loads it since the 2026-11-25 rebuild |
| `polaris_logo_clean.png` | The emblem as first published, 440 x 440 | The Helm chart's icon (`deploy/helm/polaris/Chart.yaml`) |
| `hero/coin-<pose>-384.<hash>.avif`, `-640` | The coin: the emblem as a gold and enamel medallion, path-traced in Blender from the same model, each pose seen straight on. Poses 0 to 8 answer the nine parts of the coin a pointer can rest on (4, the centre, is the coin at rest); `rx13`, `rx23` and `rx28` are the coin tipped back as the page carries it up. `coin-4-640.<hash>.webp` is the rest pose for browsers without AVIF | `404.html` (the rest pose, 4); the other poses: kept at its address; no page here loads it since the 2026-11-25 rebuild |
| `hero/coin-shadow-dir.<hash>.avif`, `hero/coin-shadow-ao.<hash>.avif` | The coin's shadow on the sky, path-traced in two layers: the lamp's, and the room's | `404.html` |
| `hero/sky-1600.<hash>.avif`, `-2400`, `-3200`; `hero/sky-2400.<hash>.webp` | The real sky round the north celestial pole for October 2026, on black, which the page screen-blends: the naked-eye stars (Yale Bright Star Catalogue, 5th edition, to magnitude 6.5) and the Milky Way of NASA's Deep Star Maps 2020 (credit: NASA/Goddard Space Flight Center Scientific Visualization Studio; Gaia DR2: ESA/Gaia/DPAC), out to 54 degrees in a stereographic view; licensed CC BY-SA 3.0 IGO (`REUSE.toml`). The WebP is for browsers without AVIF | Kept at its address; no page here loads it since the 2026-11-25 rebuild |
| `film/iii-<object>-540.<hash>.avif`, `-1080` | How it works: the objects, path-traced under the coin's lamp: a steel die (`die`), a written page (`paper`) and the Cardan grille laid over it (`grille`), a printed table of keys (`table`) and a loupe (`loupe`) | Kept at its address; no page here loads it since the 2026-11-25 rebuild |
| `film/iv-wall-<light>-1600x1000.<hash>.avif`, `-900x1400` | The rules: a polished black marble wall, path-traced once under each of its two lights: a raking light from the right (`rake`) and the coin's lamp (`lamp`). The narrow pair is for phones | Kept at its address; no page here loads it since the 2026-11-25 rebuild |
| `film/founder-128.<hash>.webp`, `-192` | The founder's portrait, his own photograph, in black and white, cut square about the face; no metadata | Kept at its address; no page here loads it since the 2026-11-25 rebuild |
| `film/trails-30m-<width>.<hash>.avif` | Half an hour of the northern sky's star trails round the pole: the stars of the Yale Bright Star Catalogue over the hero's Milky Way, turned together; licensed as the hero's sky is (`REUSE.toml`). The page lays four copies, each turned a further half hour, into the two-hour exposure of the night, behind the last act | Kept at its address; no page here loads it since the 2026-11-25 rebuild |
| `openid-certified-mark-on-white.png` | The OpenID Certified mark in the Foundation's published form: linked to the listing, its text alternative naming the certified package and version, the profile and the credential format | `index.html` |

## Conventions

- One copy of every binary, with one exception, byte for byte, because the
  site can serve only this directory: the OpenID Certified mark is also in
  `docs/assets/` (the published polaris-oid4vp README links to that path).
  `fonts/` holds cuts of the console's vendored fonts, not copies.
- Outbound links to repository documents are absolute `github.com/.../blob/main`
  URLs. A relative link would 404 on the published site, whose root is this
  directory.
