# DR drill ledger (roadmap P1.10, v9.192)

The measured recovery point and recovery time of Polaris, one row per drill,
appended by [`scripts/polaris-dr-drill.sh --record`](../../scripts/polaris-dr-drill.sh)
and never edited by hand. The monthly GitHub Actions workflow
([`.github/workflows/dr-drill.yml`](../../.github/workflows/dr-drill.yml))
runs the drill on the first of every month and commits its row, pass or fail, to a
`drill-ledger/` branch; a pull request brings it here, since `main` accepts changes only
through pull requests; every push to `main` also runs the drill in CI without recording. On a
Linux host the `polaris-dr-drill.timer` unit runs it monthly and appends to
`/var/lib/polaris/dr-drills.md`.

What a row measures ([`DR.md`](DR.md) section 1 has the targets): a
pgBackRest-archiving primary with `archive_timeout=60s` takes a full backup,
commits one marker a second for 90 seconds, is killed with SIGKILL and its
volume destroyed; a fresh container restores from the repo, replays the
archive, and the application is started against it. **RPO** is the age of
the newest recovered marker at the moment of the kill (what the archive
interval allows to be lost); **RTO** is the time from the kill to the
application reporting the database healthy (and, separately, to the database
accepting queries). Targets: RPO at most 300 s, RTO at most 14400 s.

The drill runs on a clean scratch stack with the sample data, so its RTO is
the procedure's floor, not a large deployment's; scale the restore time by
the repo size (`pgbackrest info` reports it). It does not touch a live stack.

| Date (UTC) | Version | Commit | Mode | RPO s | RTO s (database) | RTO s (service) | Backup s | Markers recovered/written | Status | Note |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|
| 2026-09-02T00:52Z | v9.192 | 31b6946+dirty | local | 41.6 | 2.8 | 4.7 | 1.5 | 54/90 | PASS | markers recovered 54/90 |
| 2026-09-02T00:55Z | v9.192 | 59dc602 | ci-monthly | 36.0 | 2.7 | 4.4 | 1.7 | 57/90 | PASS | markers recovered 57/90 |
