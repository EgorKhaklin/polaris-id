# docs/history/: the changelog archive

**Reader:** anyone who needs a ship older than the root CHANGELOG keeps, or a version number
that no longer has a tag. **Job:** hold the older entries, split by major version, unchanged,
and the map from retired version numbers to commits, so that the root file stays readable and
nothing is lost. `scripts/polaris-release-notes.sh` reads an entry from here when the root
file no longer has it.

| File | What it holds |
|---|---|
| [CHANGELOG-v9.md](CHANGELOG-v9.md) | v9.44 (3 June 2026) to v9.452 (12 September 2026), the entries moved out of the root file on 16 September 2026. |
| [RELEASES-v9.md](RELEASES-v9.md) | Every v9 version number mapped to the commit it named, with its date and subtitle. The 295 v9 tags and their GitHub releases were removed on 16 September 2026; this table is what replaces them. |

Recent ships are in the root [CHANGELOG.md](../../CHANGELOG.md).
