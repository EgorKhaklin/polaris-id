# Vendored third-party assets

Served from this directory under the console's `default-src 'self'` policy; nothing is loaded from a CDN.
Each entry names its upstream release and licence; the fonts are byte for byte as published.

| Asset | Source | Licence | Use |
|---|---|---|---|
| MapLibre GL JS | https://github.com/maplibre/maplibre-gl-js | BSD-3-Clause | carried since v9.248; the Atlas globe |
| Inter 4.1 | https://github.com/rsms/inter/releases/tag/v4.1 (Inter-4.1.zip: web/InterVariable.woff2, LICENSE.txt) | SIL OFL 1.1 | the console's text face, unmodified |
| JetBrains Mono 2.304 | https://github.com/JetBrains/JetBrainsMono/releases/tag/v2.304 (fonts/webfonts/*.woff2, OFL.txt) | SIL OFL 1.1 | identifiers, hashes and instants, unmodified |
| Cinzel | https://github.com/google/fonts/tree/main/ofl/cinzel (Cinzel[wght].ttf, git blob d218a0b9) | SIL OFL 1.1 | the POLARIS wordmark only, unmodified |
| Lucide 1.49.0 | https://github.com/lucide-icons/lucide/releases/tag/1.49.0 (lucide-icons-1.49.0.zip, sha256 66141a7b...ca1fbd5) | ISC | 73 icons combined into sprite.svg by scripts/polaris-vendor-icons.py |

## Files and SHA-256

| File | Bytes | SHA-256 |
|---|---|---|
| `fonts/cinzel/Cinzel-Variable.ttf` | 125468 | `f4d83d34d1f6c741193e4acf4b3dff9531e5a67b6aa65228d00a7db72a4e0f34` |
| `fonts/cinzel/OFL.txt` | 4383 | `f2b3029aba64c378bf0963b62945eee15e564fe4330b934c8f2eb058282b5e83` |
| `fonts/inter/InterVariable.woff2` | 352240 | `693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3` |
| `fonts/inter/OFL.txt` | 4380 | `262481e844521b326f5ecd053e59b98c8b2da78c8ee1bdbb6e8174305e54935a` |
| `fonts/jetbrains-mono/JetBrainsMono-Medium.woff2` | 93824 | `086c48dfbea9ddaff1320f7e09399b8e2924e88ce67453721255db3bdbb5a353` |
| `fonts/jetbrains-mono/JetBrainsMono-Regular.woff2` | 92164 | `a9cb1cd82332b23a47e3a1239d25d13c86d16c4220695e34b243effa999f45f2` |
| `fonts/jetbrains-mono/OFL.txt` | 4399 | `30f0c136e3c88e422d0791acd97238870f9054a9729bc34cf2ff0d4ed8cac4ad` |
| `lucide/LICENSE` | 3208 | `b495047bd93a9b06913511076f504daba17d5bbeb3e0650f3bb53a4220329c57` |
| `lucide/sprite.svg` | 22668 | `07b2c3543c2c27c304aa8e1036657b49546572fc0f859b1ab6af7c4edb550d2a` |
| `maplibre-gl.css` | 70024 | `ab1e70d59ec40465bae7e7030da2f3ccf28133fd502e62bd598eefbadfd7a732` |
| `maplibre-gl.js` | 1056837 | `45a9b07a9189ce56054c620a947ccf41e291e58c95e9b61533b740aaa65ee5cb` |
