# Per-authority isolation: the review, and what it changed

**Reader:** an assessor asking whether one authority's operators can see another's data, or an
operator deciding whether to host two authorities in one instance. **Job:** report what the
review found, what was added, and the part that cannot be fixed by adding anything.

## What the review found

A Polaris instance can hold many agencies. The schema permits it and the shipped seed
demonstrates six.

Before this work, an operator was **global**:

- `AppUser` had no agency binding. The roles are `admin`, `operator` and `auditor`, and none of
  them names an authority.
- Of 74 operator routes behind `login_required`, **sixteen read credential or holder data with
  no issuing-agency filter at all**. The token list is the plainest example: it selects every
  token, joined to every holder, with no notion of whose it is.

In the topology the [ADR](federation-topology.md) chose, each authority runs its **own**
instance, which makes a global operator correct. Nothing enforced that assumption, stated it at
the operator surface, or would have noticed a deployment that violated it.

## What was added, and where it lives

The isolation is a **database guarantee**, not an application one. The application sets a
session value saying who is asking; the policies decide what they see.

That division is the point. Patching sixteen query bodies would be exactly the
application-level policy this schema exists to refuse, and it would be correct only until the
seventeenth route. A policy the database enforces cannot be forgotten.

| Table | Scoped by | Why that column |
|---|---|---|
| `IdentityToken` | `issuing_agency_id` | A credential belongs to the authority that issued it. Everything credential-bearing joins through this table, so a row an operator cannot see contributes nothing to any join. |
| `VerificationEvent` | `requesting_agency_id` | An event belongs to the authority that asked, which is a different relation from issuance. |
| `TokenLifecycleEvent` | `actor_agency_id`, or NULL | Who acted, not who issued. A NULL actor stays visible to everyone: hiding a transition nobody is recorded as having made would make the audit trail read as though it never happened, which is the opposite of what an append-only audit of record is for. |

`AppUser.agency_id` is nullable, and **NULL means unscoped**. That is the default and it is
correct for a single-authority instance. Every policy is permissive when the session value is
empty, so unauthenticated API paths, the relying-party surface and the test suites are
unaffected by this change.

## The part that cannot be fixed by adding policies

**An individual is not owned by an authority.** A person is a person; two authorities may
both have issued to them over time, and C3's one-active-credential rule constrains credentials,
not people. There is no honest per-authority policy for `Individual`, and inventing one would
assert an ownership the model does not have.

So in a shared instance these policies **bound** what an operator sees. They do not achieve
isolation, because holder identity remains visible across authorities.

That is the review's substantive finding, and it changes the status of the topology decision:
**one authority per instance is load-bearing, not stylistic.** An operator considering two
authorities in one database should read that sentence as the answer, not as a preference.

## One trap, recorded

The natural way to write a policy with a permissive default is:

```sql
USING (coalesce(current_setting('polaris.operator_agency_id', true), '') = ''
       OR issuing_agency_id = current_setting('polaris.operator_agency_id', true)::INTEGER)
```

It is wrong. PostgreSQL does not guarantee that `OR` short-circuits, so the cast on the right is
evaluated even when the left branch is true, and an unscoped session dies with
`invalid input syntax for type integer: ""`. The failure is not confined to the isolation: every
query against the table raises, so an unauthenticated instance stops serving entirely. The
shipped form never lets the cast see an empty string:

```sql
USING (issuing_agency_id = coalesce(
           NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
           issuing_agency_id))
```

`NULLIF` turns the empty or missing setting into `NULL`, and the `coalesce` then compares the
column with itself, which is true for every row. The isolation drill caught this on its first
run, before the change left the working tree. `check_per_authority_isolation` refuses any
`current_setting` cast that is not guarded, so it cannot come back.

## What is still not enforced

Nothing stops a deployment from running two authorities in one instance and binding no
operators. The review deliberately did not add a boot-time refusal: an instance that legitimately
holds several agencies for a single-issuer topology, or the shipped seed itself, would be
refused for a configuration that is not wrong. What exists is the mechanism and the finding; the
placement decision is the operator's, as the ADR already says of everything else in this layer.

## Proven by

`scripts/polaris-authority-isolation-drill.py` on every push: an operator bound to one
authority cannot read another's credentials **through a raw SQL query**, not merely through the
application, which is the only version of that claim worth making. It also asserts the
permissive default, and that holder identity is still visible, so the limitation above stays
demonstrated rather than merely written down.

`check_per_authority_isolation` pins the policies, the operator binding, the permissive default,
the unguarded-cast trap above, the fact that the scope is applied to every connection `get_db`
hands out, and the pairing between `is_local=false` and the per-request connection: put a pool
behind `get_db` without resetting the scope on checkout and one operator's authority is inherited
by the next request on that connection, which is a cross-authority read attributed to the wrong
person.
