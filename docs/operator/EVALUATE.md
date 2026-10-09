# Evaluating an install

`scripts/polaris-evaluate.sh` judges the install it runs on and writes a report you can keep: for an
operator checking their own deployment, or anyone deciding whether Polaris holds up on their machine.

```bash
cd /opt/polaris
sudo scripts/polaris-evaluate.sh                                     # any install; changes nothing you would mind
sudo scripts/polaris-evaluate.sh --pack pack.json --rp-config rp.json   # also one of your credentials, as your relying party
sudo scripts/polaris-evaluate.sh --notional --operator NAME --password-file FILE   # notional data only, see below
```

Read `~/polaris-evaluation-<UTC>/report.md`: in your home and owned by you, sudo included (`--out DIR`
names another new directory; an existing one is refused). Exit 0: no probe failed. Exit 1: a probe failed,
and the last line names it. Exit 2: no stack here to evaluate, or an input file is unreadable.
`--rp-config` is a JSON file with the `client_id` and `client_secret` that `polaris-rp-register.sh` printed.
The edge is `https://$POLARIS_DOMAIN` unless `--url` names another (an edge on a port other than 443);
on a private CA, `--cacert FILE`; on `localhost` the edge's local root is read from the edge itself.

## What it runs

| Rows | Probe | A sound install |
|---|---|---|
| A | `polaris-doctor.sh`: services, secrets, configuration, the edge, the app's health, the key register, backups | every component ok |
| B | the database's own self-test (the one behind `/athena`), on the application's connection, every statement rolled back | each forbidden write refused by the rule that should refuse it |
| C | the published trust list against the key custody signs with | the key is published and active |
| D | `polaris-verify`, the version this release ships (from PyPI, or this checkout when it is ahead), offline, against the published key: the credential, then five tampered copies | the credential accepted, every copy refused |
| E | a relying party verifying online, two tampered copies, and the lifetime of a status assertion | accepted, refused, a number |
| F | with `--notional`: one credential issued through the console, revoked (co-signed), verified again | the revoked credential refused online |
| G | the version, and the image each service runs | reported, not judged, until releases publish images |

A refusal counts only when it is an answer: a verifier or an API that gives no verdict fails its row,
and the tampered copies are not judged when the genuine credential was refused, since refusing everything
proves nothing. A probe that cannot run fails its row; the report is written either way.

## What it changes

By default, nothing you would mind. The relying-party API keeps no record of a verification, and the
self-test rolls back every statement: what remains is its refused statements as ERROR lines in the
PostgreSQL log, tagged `application_name=polaris-athena-selftest` ([OPERATIONS.md](OPERATIONS.md)), and the
sequences its rolled-back inserts advanced. The verifier's venv and the credential's copies live in a
temporary directory removed at the end; the report never holds them.

`--notional` also leaves one relying party registration (`evaluation-<UTC>`) and one notional holder with
one credential, revoked by the run; if the revocation fails, the report says the credential is still active
and to revoke it in the console. Use it only on a database that holds notional data: nothing can check that,
and the report records that you said so. The revocation is co-signed by a second authority
(`--witness-agency`, default 2), because one authority alone may not pass its revocation rate bound,
and on a small database one revocation does.

## The report

`report.md` and `report.json`, readable by their owner only. Each row says what was attempted, what a
sound install does, and what this one did. The verdict digest is a hash of the verdicts alone, so two
runs on the same release give the same digest though their times and numbers differ. No password or
secret the run used is written.

## What a run does not establish

- It is not a security review, an audit or a penetration test: it runs the probes above and nothing else.
- A PASS means a probe behaved as a sound install behaves, at that moment, on that host.
- Notional data says nothing about handling real identity data: that needs an independent review, your
  own data-protection assessment and a pilot ([PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md)).
- Release provenance is reported, not judged, until the images are published and signed.

## How it is checked

CI's fresh-host job runs it after the install, then grants the application a
privilege the database withholds and, separately, stops the edge: each run must fail and name what
broke. `check_evaluate_wired` keeps the probes, the controls and this page in place.
