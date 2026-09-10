# A second region: why a standby cluster, and what it costs

**Reader:** an operator deciding whether to run two regions, or an assessor asking what the
second one actually guarantees. **Job:** state the shape, the reason it is that shape, and
the recovery point it does not eliminate.

The HA profile survives a node dying: Patroni's lease moves and another member in the same
region takes over, with no data loss, because the members are close enough to replicate
promptly and share a lease store. It does not survive the region.

## Why not simply add a third member "in region B"

Because it puts the wide-area network inside the quorum, in three places at once.

**The lease store.** Patroni's leader lease lives in etcd, and a member can only participate
if it can reach that store. Stretching the etcd cluster across regions means every lease
renewal crosses the WAN, and a partition between regions becomes a partition of the consensus
itself. A three-member etcd split two-and-one across two regions loses quorum when the
two-member side goes dark, which is exactly the outage the second region existed to survive.

**Write latency.** A synchronous member across the boundary puts the round trip on every
commit in region A. That is a real product decision an operator may want, but it should be
chosen, not inherited from a topology diagram.

**Blast radius.** A member of region A's cluster that lives in region B is still region A's
problem when region A's lease store is unreachable. The regions are not independent; they are
one cluster with a long wire.

## The shape that ships

A **standby cluster**: region B is a separate Patroni cluster, with a different scope, its own
lease store, whose leader streams asynchronously from region A's primary through the router
that follows region A's lease.

| Property | Consequence |
|---|---|
| Its own lease store | Region A going dark takes no part of region B's consensus with it. |
| A different cluster scope | Region B never competes for region A's leader key. |
| Streams through region A's router, not a fixed member | A failover *inside* region A does not break replication to B. |
| Asynchronous | Region A's commit latency does not depend on region B. |
| Elects no primary of its own | Two regions cannot both accept writes; region B refuses them until promoted. |

## The cost, which is the recovery point

Asynchronous replication means the recovery point is **not zero**. Promoting region B accepts
the writes region A acknowledged that had not yet crossed the wire. That is a real number of
real records, and a runbook that does not say how far from zero is one nobody can plan
against.

So it is measured rather than asserted.
`scripts/polaris-region-evacuation-drill.sh` runs the whole evacuation on every push, under a
live write stream, recording every acknowledged write as it goes so the number is knowable
after the region is gone. It reports:

- **RTO**, the time from the decision to evacuate until region B accepts a write.
- **RPO**, in rows: acknowledged in region A, absent from region B.

and it asserts two things that matter more than either number:

- **No invention.** Every row region B holds must be one region A acknowledged. A row region A
  never acknowledged would mean the regions had diverged, and a promotion would publish writes
  no client was ever told succeeded. A recovery point is a stated cost; divergence is a
  correctness failure.
- **A contiguous prefix.** What crossed must be an unbroken run, not a perforated one. A
  standby holding 1-40 and 45-60 has *skipped*, which is a different failure from lagging and
  would not be caught by counting rows.

The region is cut the way a region goes dark: the database members, the router **and** the
lease store, all at once. Stopping only the leader is the failover drill's scenario.

## What this does not solve

**Placement.** Two regions are two placements and one WAN link, and that is the operator's.
The compose file proves the mechanism on one host; in production
`POLARIS_PATRONI_STANDBY_HOST` names region A's real address, and etcd needs TLS between
members once it leaves a single host's internal network.

**Automatic promotion.** Region B is promoted by an operator running one command, deliberately.
An automatic cross-region promotion would have to distinguish "region A is gone" from "region A
is unreachable from here", and getting that wrong produces two primaries on two timelines,
which is the one state with no clean recovery. The runbook's first step is confirming region A
is actually gone.

**Coming back.** When region A returns, its database holds a diverged timeline. It is rebuilt
as a standby of region B or restored from the archive; it is never brought back as a primary.
[../operator/DR.md](../operator/DR.md) carries the procedure.

**Zero data loss.** Synchronous cross-region replication would give it, at the cost of the
WAN's round trip on every commit in region A. That is a different product and the repository
does not choose it for a deployment.

## Proven by

`scripts/polaris-region-evacuation-drill.sh` on every push, and
`check_multi_region_dr`, which pins the standby-cluster shape (its own lease store, its own
scope, asynchronous), the drill's measurement of both numbers, and the runbook's statement of
the recovery point before the procedure rather than after it.
