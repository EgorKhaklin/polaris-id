# govulncheck reports for scripts/test_govulncheck_gate.py

Each file is govulncheck v1.9.0 `-mode=binary -format json` output, cut to its `config`, `SBOM` and
`finding` messages, read against vuln.go.dev's database as modified 2026-10-27T21:16:18Z. The
`SBOM` line comes from a second run on the same binary (same sha256, same database), whose
findings were the same set.

| File | Binary |
|---|---|
| `gosu-pre.json` | `/usr/local/bin/gosu` in `postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea` (linux/amd64), sha256 `52c8749d0142edd234e9d6bd5237dff2d81e71f43537e2f4f66f75dd4b243dd0`: gosu 1.19, Go 1.24.6, the gosu `polaris-postgres` carried before it compiled gosu 1.20 |
| `caddy-shipped.json` | `/usr/bin/caddy` in `polaris-caddy` built from `polaris_web/Dockerfile.caddy` (linux/arm64), sha256 `414a657b08d718f0dd3bb2c564ad59ef2daaaaf6cf3f7f51e8de403fed408a43`: Caddy 2.11.4 with its module floors, Go 1.26.10, symbol table kept |

The test builds ELF files with the section names of three binaries: the two above, and the
stripped `/usr/bin/caddy` in `caddy:2.11.4-alpine@sha256:6aeddd44c3078b0f9a35206472a11420648a79c184603ef95957d0a20044cb2b`
(linux/amd64), sha256 `b7105518e3ed1c0761f232e44fc09345535533c9cb0abf0e12809416c7ac64d9`. In the
first two `.symtab` is a non-empty SHT_SYMTAB section, as the test builds it; the stripped one has
no SHT_SYMTAB section.
