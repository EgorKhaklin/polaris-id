# Chaos drills

The standing chaos program (roadmap P2.11). Two instruments, two cadences:

- **Every push:** `scripts/polaris-chaos-test.sh` runs in the product-test
  job. It asks whether the *application* fails safe: the database gone
  mid-recovery, the ZK prover binary absent, an epoch close interrupted.
  Every scenario must end in a refusal, never a silent success. It is a
  gate, not a drill: a red run blocks the merge.
- **Weekly, and on demand:** `scripts/polaris-chaos-drill.sh` runs against
  the booted blue-green stack (the `chaos` workflow, Mondays 05:47 UTC, and
  `workflow_dispatch`). It asks what the *stack* does when a component
  dies, with real traffic against the edge and a real paging path: a
  Prometheus scraping the app containers with the shipped alert rules, the
  shipped Alertmanager configuration, and a webhook sink standing in for the
  pager. One row is appended below per run, PASS or FAIL, committed by the
  workflow.

Scenarios in the weekly drill, each under continuous traffic:

| | Induced failure | Must hold |
|---|---|---|
| A | one app colour crashed (SIGKILL of its init from the host pid namespace) | zero dropped requests; the container restarts on its own within 60 s |
| B | both app colours stopped for 150 s | the generator sees the outage; `PolarisAppDown` reaches the sink; service back within 60 s of `compose start` |
| C | redis crashed (SIGKILL) | the app keeps serving; redis restarts on its own; readiness healthy within 60 s |
| D | postgres crashed (SIGKILL) | crash recovery within 90 s; the app containers are not replaced |
| E | pgbouncer partitioned for 15 s | the database path recovers within 60 s of the reconnect |

A crash is a SIGKILL of the container's init from the host pid namespace.
`docker kill` is not one: Docker records it as a manual stop and the restart
policy does not apply, so a container "killed" that way stays down. The
drill's first run found exactly that, in its own primitive. The partition has
the same trap: `docker network connect` without `--alias` brings a container
back under its container name only, and the service name the app dials is
gone. The drill reconnects with the aliases it captured and proves the app
resolves `pgbouncer` again before it reads the recovery clock.

The ceilings are assertions. A stack that recovers slowly fails the drill
rather than widening a number nobody re-measures. Findings feed checks: a
scenario that exposes a gap becomes a `polaris_checks` check with a
detection test before the fix ships, the same path the DR and window drills
follow.

Run it by hand against a booted stack (the rolling and window drills use the
same overlays):

```sh
export POLARIS_DOMAIN=localhost
export POLARIS_COMPOSE_EXTRA="-f docker-compose.citest.yml -f docker-compose.bluegreen.yml"
scripts/polaris-chaos-drill.sh --record        # appends the row below
```

The Recovery column lists each scenario's time to healthy in seconds. Page s
is how long after the outage began that `PolarisAppDown` reached the sink
(the rule's `for` is two minutes; the sev1 route has no group wait).

| Date (UTC) | Version | Commit | Mode | Recovery (A one colour, B both colours, C redis, D postgres, E pgbouncer) | Page s | Status | Note |
|---|---|---|---|---|---|---|---|
| 2026-09-05T11:20Z | v9.242 | 300f4ca+dirty | local | A=5s B=3s C=10s D=2s E=0s | 121 | PASS | one colour: 0 drops; outage paged; postgres crash window 0.6s, partition window 10.1s; no app restart |
| 2026-09-05T11:34Z | v9.242 | 7e97cdd | ci | A=6s B=3s C=10s D=1s E=0s | 122 | PASS | one colour: 0 drops; outage paged; postgres crash window 0.0s, partition window 15.0s; no app restart |
| 2026-09-05T11:47Z | v9.242 | 928bb50 | ci | A=6s B=1s C=10s D=3s E=2s | 121 | PASS | one colour: 0 drops; outage paged; postgres crash window 1.9s, partition window 16.3s; no app restart |
| 2026-09-07T10:50Z | v9.259 | 1ce7cd7 | ci | A=6s B=2s C=10s D=1s E=1s | 122 | PASS | one colour: 0 drops; outage paged; postgres crash window 0.0s, partition window 11.2s; no app restart |
| 2026-09-14T11:07Z | v9.458 | 987c123 | ci | A=6s B=3s C=10s D=1s E=1s | 121 | PASS | one colour: 0 drops; outage paged; postgres crash window 1.1s, partition window 15.2s; no app restart |
