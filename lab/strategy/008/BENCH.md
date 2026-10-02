# Bench: the operator console at two million persons

Lab evidence for [record 008](../008-population-scale.md). One laptop (Apple silicon, 16 GB),
PostgreSQL 16.14, the application in-process (Flask test client, so the time is the application and
the database, not the network), signed in as the seeded admin. Medians: three runs on the seed,
one run after a warm-up at scale, more where a figure was re-timed (noted below).

- **Seed:** `polaris_sql/00_load_all.sql` and the migrations.
- **Scale:** the same, then [gen.sql](gen.sql) with `n=2000000 v=10000000`: 2,000,012 persons,
  3,640,007 credentials (each person one ACTIVE, half a RESERVE, a quarter a REVOKED one, some
  EXPIRED and LOST), one 64-byte signature each (a real ML-DSA-65 signature is 3,309 bytes),
  6,140,016 lifecycle events and 10,000,010 verifications spread over the month before loading. The
  September events land in the DEFAULT partition, because a fresh load creates partitions from the
  current month on.
- **Before:** the committed console (9cc3e95f). **After:** step 1 of the record (the Overview, the
  maintained counts, the indexes of migrations 2026-10-01-004 and -005).

Falsifier 1 holds for a page when its time at scale is at most three times its time on the seed.

| Page | Seed (ms) | Scale before (ms, page size) | Scale after (ms) | After / seed | Falsifier 1 |
|---|---|---|---|---|---|
| `/dashboard` | 88 | 10416 (40 kB) | 118 | 1.3 | holds |
| `/tokens` | 6 | 25 (78 kB) | 9 | 1.3 | holds |
| `/tokens?status=ACTIVE` | 6 | 11 (79 kB) | 8 | 1.3 | holds |
| `/tokens?page=2` | 6 | 12 (79 kB) | 8 | 1.3 | holds |
| `/tokens?page=5000` | 6 | 284 (80 kB) | 293 | 47.3 | fails |
| `/tokens/1` (a seed credential) | 35 | 278 (22 kB) | 34 | 1.0 | holds |
| `/tokens/<newest>` | 35 | 188 (21 kB) | 38 | 1.1 | holds |
| `/investigate/token/<newest>` | 23 | 1237 (17 kB) | 132 | 5.8 | fails |
| `/individuals` | 6 | 17 (120 kB) | 15 | 2.6 | holds |
| `/individuals?page=5000` | 5 | 42 (123 kB) | 37 | 6.9 | fails |
| `/individuals?q=Person+1234567` | 6 | 10 (120 kB) | 10 | 1.8 | holds |
| `/individuals/<newest>/edit` | 5 | 6 (15 kB) | 6 | 1.1 | holds |
| `/investigate/individual/<newest>` | 18 | 819 (18 kB) | 20 | 1.1 | holds |
| `/individuals/enrollment` | 10 | 5640 (21 kB) | 5556 | 578.8 | fails |
| `/agencies` | 6 | 8 (19 kB) | 8 | 1.4 | holds |
| `/agencies/1/edit` | 6 | 8 (16 kB) | 8 | 1.4 | holds |
| `/verifications` | 13 | 22 (60 kB) | 22 | 1.7 | holds |
| `/verifications?page=5000` | 13 | 3407 (60 kB) | 3128 | 246.3 | fails |
| `/verifications/new` | 10 | 28943 (367,046 kB) | 24304 | 2336.9 | fails |
| `/anchors` | 8 | 15 (17 kB) | 14 | 1.7 | holds |
| `/epochs` | 6 | 7 (16 kB) | 6 | 1.0 | holds |
| `/epochs?epoch_id=1` | 9 | 11 (17 kB) | 10 | 1.1 | holds |
| `/federation` | 9 | 11 (22 kB) | 10 | 1.1 | holds |
| `/duress` | 14 | 168 (16 kB) | 153 | 11.0 | fails |
| `/sql` | 4 | 5 (16 kB) | 8 | 2.1 | holds |
| `/uc1/issue` | 10 | 12 (20 kB) | 16 | 1.5 | holds |
| `/uc4/activate-reserve` | 11 | 18774 (328,958 kB) | 20192 | 1852.4 | fails |
| `/uc5/bind-device` | 6 | 11779 (219,310 kB) | 12437 | 2038.9 | fails |
| `/uc6/migrate` | 9 | 39546 (628,802 kB) | 39284 | 4464.1 | fails |
| `/uc7/warrant-audit` | 6 | 13221 (289,731 kB) | 13478 | 2209.5 | fails |
| `/uc8/revoke` | 9 | 19450 (458,264 kB) | 19674 | 2287.7 | fails |
| `/uc9/queue` | 6 | 11 (16 kB) | 10 | 1.7 | holds |
| `/uc9/initiate-recovery` | 9 | 1510 (18 kB) | 1726 | 183.6 | fails |
| `/atlas` | 36 | 5133 (44 kB) | 5646 | 156.8 | fails |
| `/athena` | 17 | 27 (33 kB) | 30 | 1.7 | holds |
| `/settings/webauthn` | 6 | 9 (15 kB) | 12 | 2.1 | holds |
| `/uc9/decide/1` | 8 | 13 (19 kB) | 15 | 1.8 | holds |

Re-timed: the Overview over seven runs on both databases; `/duress` and `/verifications?page=5000`
over three runs at scale, after a first pass that read 877 ms and 29.5 s from a cold cache.

## What the step changed, and what it did not

- **The Overview** went from 10.4 s to 0.12 s, against 0.09 s on the seed.
- **A credential's page, and both investigation pages,** now read the credential's verifications
  through `idx_verificationevent_token_time`; they scanned every verification.
  `/investigate/token` still fails: its view counts the credential's verifications on every
  view and its timeline is unbounded (next step).
- **Still failing, and the next steps of the record:** the seven operation forms (each renders a
  dropdown of a whole population: 219 MB to 629 MB of HTML here, and each would be unservable at
  eight billion), the lists' offset paging, the enrollment summary (a `DISTINCT ON` over every
  enrollment event), `/duress` (two full counts), the recovery form and the Atlas.

## Step 2: the operation forms (2026-10-01)

Each form now opens on one record, found by lookup (`polaris_web/lookup.py`), and the lookups are
POSTs, timed here with the same harness ([bench.py](bench.py), five runs after a warm-up). The
seed is the seed load with three more credentials, so that a holder has an active credential and
two reserves; the scale database is the one above, with migration 2026-10-01-006's index (built
in 1.8 s over the two million persons; 77 MB). "Before" is the scale time after step 1, which did
not change these pages.

| Page | Seed (ms) | Scale before (ms, page size) | Scale after (ms) | After / seed | Falsifier 1 |
|---|---|---|---|---|---|
| `/uc4/activate-reserve`, opened on the lost credential | 11.8 | 20192 (328,958 kB) | 13.8 | 1.2 | holds |
| `/uc5/bind-device`, opened on a credential | 6.5 | 12437 (219,310 kB) | 7.5 | 1.2 | holds |
| `/uc6/migrate`, opened on a credential | 12.2 | 39284 (628,802 kB) | 13.4 | 1.1 | holds |
| `/uc7/warrant-audit`, opened on a person | 8.7 | 13478 (289,731 kB) | 9.1 | 1.0 | holds |
| `/uc8/revoke`, opened on a credential | 9.6 | 19674 (458,264 kB) | 10.1 | 1.1 | holds |
| `/uc9/initiate-recovery`, opened on a person | 14.2 | 1726 (18 kB) | 16.0 | 1.1 | holds |
| `/verifications/new`, opened on a credential | 12.1 | 24304 (367,046 kB) | 12.5 | 1.0 | holds |
| POST `/find/credential`, by number | 12.2 | | 12.4 | 1.0 | holds |
| POST `/find/credential`, by token value | 10.4 | | 10.1 | 1.0 | holds |
| POST `/find/credential`, by card serial | 9.7 | | 9.8 | 1.0 | holds |
| POST `/find/person`, name and date of birth | 5.8 | | 6.9 | 1.2 | holds |

Every page opened on a record is 16 to 21 kB. At scale the person lookup listed the first 20 of the
people born that day whose names begin as typed, and said there were more (22.5 kB); on the seed
it found one person and went straight to the page.

## Estimates checked against exact counts (falsifier 4)

Both estimators the step first tried were measured here and dropped (record 008, section 11): a
block sample put statuses 6% high, and a rate times a window missed the 24-hour verification count
by 57%. The Overview now shows only exact counts, counts capped at a stated bound, and shares that
name the slice they describe.
