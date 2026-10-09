# Synchronous replication in the HA profile: a failover loses no acknowledged write

**Reader:** an operator running the HA profile or the chart, or an assessor asking what a
database failover can lose. **Job:** state the default, why it is the default, what it costs
(measured), and how to choose the other side.

The HA profile and the chart run Patroni's `synchronous_mode`, not strict, by default (lab record
017, gate row OP-6). A commit returns to the application only after the replica has flushed it to
disk, and Patroni promotes only the replica it names synchronous, so a write the application saw
succeed survives the loss of the leader.

## Why this is the default

An acknowledged write in Polaris is often a withdrawal of trust: a revocation, a compromised
authority key, a locked account, a duress event. Under asynchronous replication a failover can
lose the last of them, and the failover drill has seen it: in one CI run, a leader cut off from
its lease store had acknowledged two inserts the replica never received, and the replica took
over without them. A revocation lost that
way is not an outage; the credential reads as good again and nothing says so.

The runbook used to leave the choice to the operator. The synthesis keeps what that stance got
right (the trade is real and the operator can still take the other side) and drops what it got
wrong (a plug-and-play default that silently loses acknowledged revocations).

## What it costs

**Commit latency.** Every commit waits for the replica to receive its WAL and flush it: one round
trip to the replica and one disk flush there, on top of the leader's own. On the single-host
profile the members share a machine and a bridge network, so the round trip is small and the
replica's flush is most of the added cost.

**The replica's loss.** When the replica goes, the commits in flight wait for it until Patroni, on
its next loop (`loop_wait`, 5 s here), stops naming it synchronous; then they complete and writes
continue on the leader alone. The failover drill's fifth scenario kills the replica and requires
the leader to keep its lease, no insert to fail, and the longest stall to stay under 30 s. It records
the stall on every run (`replica_lost.longest_stall_s` in its summary).

**Liveness.** Not strict: when the replica is lost the leader stops waiting for it and keeps taking
writes alone. While it does, its newest writes exist on one member. If the leader is lost too in
that window, Patroni does not promote the replica that missed them: the cluster is read-only until
the leader returns. That is an outage, not a lost write. `synchronous_mode_strict` would refuse
writes instead whenever no replica is synchronous; Polaris does not turn it on, because with two
members every replica restart would stop writes.

**Across hosts.** On one host the replica is a network hop away. Across hosts every commit pays the
round trip to the replica plus its flush, so place the members close (the same region, as
[multi-region.md](multi-region.md) argues for the lease store).

## Choosing the other side

`POLARIS_PATRONI_SYNCHRONOUS_MODE=off` (Compose) or `postgres.patroni.synchronousMode: false` (the
chart) bootstraps an asynchronous cluster: lower commit latency, and a failover may lose the writes
the replica had not received (usually milliseconds of them; FAILOVER.md section 6). The setting is
written into the cluster's configuration when it is first created. An existing cluster changes
with `patronictl edit-config --set synchronous_mode=true` (or `false`) on a member.

## Evidence

`scripts/polaris-failover-drill.sh` reads the mode from the cluster's configuration. With it on, it
requires the replica to be the synchronous standby before each scenario and fails on any
acknowledged insert missing from the surviving history after a lost leader, a leader cut from the
lease store, or a switchover. CI runs it on every push. `check_failover_keeps_acknowledged_writes`
holds the default, the drill's assertion and this record together.

**What would show this is wrong:** the drill finding an acknowledged insert lost with the mode on
(the mechanism does not hold), or a commit latency cost large enough that operators turn it off
(the default is the wrong side of the trade for them).
