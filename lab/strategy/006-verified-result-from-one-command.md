# 006: a stranger's verified result from one command

**Opened 2026-09-30.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md).
State: OPEN, record only.

---

## The finding that started it

The operating contract (section 4) holds every artifact at a release candidate "until an operator
who is not the author reaches a verified result without help". The README's one command,
`./Polaris.command`, starts the laptop stack, and the README says what that stack signs with: "a
named development placeholder, not ML-DSA-65, so `polaris-verify` reports what it issues as not
authenticatable". So the one command a stranger is handed cannot produce the result the version
is waiting for, and no amount of care on their side changes that.

The production path can. The production image builds liboqs, and
`scripts/polaris-generate-secrets.sh` mints an ML-DSA-65 key with it, but that path asks for a
domain, TLS and a deploy. CI already runs the same stack on localhost:
`polaris_web/docker-compose.citest.yml` changes only the TLS edge (Caddy's internal CA on 8443),
and the job "Full prod compose boots + serves end to end" runs it on every pull request. Nothing
but packaging stands between a laptop and a real signature.

- **Kept:** the placeholder stays the laptop default. A laptop holds no key material unless asked,
  and a placeholder verdict is labelled so it cannot be mistaken for a real one (section 5).
- **Kept:** the 1.0.0 condition, unchanged. It asks for a stranger's result, not the author's
  demonstration.
- **Dropped:** the unstated equation that trying Polaris on a laptop means trying the placeholder.
- **New position:** a second command that runs the production stack as it ships, on the
  stranger's machine, under a key minted there. It issues one credential to a notional person
  and hands over the pack and the instance's anchor for `polaris-verify` from PyPI. The key,
  the stack and the check are all the stranger's own.

## 1. What capability is being considered?

One command that:
- builds the production images;
- generates the secrets, including an ML-DSA-65 key;
- starts the production stack on localhost behind the internal-CA overlay;
- issues one credential to a notional person;
- writes its authenticity pack and the instance's issuer anchor to files;
- prints the `polaris-verify` command that checks them.

Then two more things to see: the same credential revoked, which `/api/v1/verify` reports as
authentic but not currently authoritative, and one write the schema refuses to the application
role.

## 2. What problem would it solve?

The version cannot move until a stranger reaches a verified result. Today the shortest
documented path to one runs through a domain name and a deploy.

## 3. Who would plausibly need it?

- The evaluator the contract names.
- A reviewer in their first hour.
- The weekly stranger's-path routine, which walks the published packages and cannot reach a
  real issuer signature today.

## 4. What already solves it?

- **The README's "Try it"** verifies a published sample under a published sample key. That is
  real cryptography, but the author's key and the author's credential.
- **The single-host deploy** is real, but it is for a server with a domain.
- **CI's prod-compose job** is real and local, but it runs only as a CI job, and it checks
  health, not a credential.

## 5. Can Polaris interoperate instead of rebuild?

Nothing is rebuilt. The script composes what exists: the production compose, the citest overlay,
the secret generator, the CLI, and `polaris-verify` from PyPI. The only new file is the script
that puts them in order.

## 6. What unique advantage could Polaris obtain?

A stranger can check a post-quantum signature from their own stack, under a key minted on their
own machine, in minutes. The claim the project is built on becomes falsifiable by anyone with
Docker.

## 7. What happens if Polaris does NOT build it?

The candidate waits on a stranger who first reads a deploy guide, owns a domain, and knows which
of four paths yields a real signature.

## 8. What other work would be delayed?

None in the 005 line, whose surfaces this does not use. The first cut leaves out the ZK
presentation and wallet copies. Each can join once the base path is proven.

## 9. Can the idea be tested cheaply in LAB first?

1. By hand, on one machine:
   - generate secrets into a scratch directory;
   - bring up the production compose with the citest overlay;
   - issue one credential and fetch its pack and the anchor;
   - run `polaris-verify` from a fresh venv.

   Time each step, and write down every command a stranger would have to know.
2. Script exactly those commands under `lab/`, and run the script from a fresh clone.
3. Only then give it a README line, and point the weekly stranger's-path routine at it.

## 10. What evidence would prove the bet wrong?

- **It is not one command.** From a fresh clone on a machine with Docker, the script cannot
  reach `polaris-verify ... exit 0` on a credential its own stack issued unless the reader edits
  something. Then packaging is not the gap. Record what is, instead of shipping the script.
- **It is not the production stack.** The script needs a flag, setting or skipped check that
  exists only to make it pass. The overlay may change the TLS edge, as CI's does, and nothing
  else.
- **It is too slow to be tried.** It takes more than 15 minutes from `git clone` to the verified
  result on a laptop, build included. Then the image build is the gap, and the answer would be a
  published image, which is the owner's decision.
