# 006: a stranger's verified result from one command

**Opened 2026-09-30.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md).
State: OPEN. Steps 1 to 3 done (2026-09-30): the verified result is one command, `lab/strategy/006/try.sh`,
and a workflow runs it from clean images every night.

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

## Step 1: the walk by hand (2026-09-30)

From a fresh checkout of main (68ffcfd2) on a laptop (macOS, Docker Desktop, 8 CPUs),
`polaris-verify` 1.0.0rc4 from PyPI verified a credential that the local production stack
issued: `signature_valid: True`, `issuer_trusted: True`, exit 0. The key was the ML-DSA-65 key
`polaris-generate-secrets.sh` minted on that machine. From checkout to verified result took nine
minutes, about five of them machine time, mostly the image build (277 s on a warm layer cache).

The commands a stranger needs, in order:
1. Build the images.
2. Generate the secrets.
3. Start the stack with the citest overlay.
4. Create an operator.
5. Log in and issue through the operator console. The browser warns about Caddy's local
   certificate authority; the walk trusted its root certificate.
6. Fetch the authenticity pack.
7. Write the anchor from the public half of the minted key.
8. Install `polaris-verify` and run it.

What stood in the way:
- **Fixed:** `polaris-create-operator.sh --target=docker-stack` could not create an account.
  psql ran inside the container and was handed a file that exists only on the host.
  `polaris-generate-recovery-code.sh` and `polaris-recover-admin.sh` had the same defect, so admin
  recovery could not run in that mode either. All three now send the SQL on stdin, and a check
  keeps it that way.
- **Fixed:** the CLI's README told readers to install a package that is not published. It now
  installs from a clone. The CLI is not in the production image.
- **Open:** the operator script needs werkzeug in the host's python3. The one command must hash
  inside the image, or bring its own.
- **Open:** the production compose shares a project name and one container name with the laptop
  stack. Running both needs a project name and reset container names, which the one command must
  set.
- **Open:** the build time on a clean machine is not measured, because this cache was warm. liboqs
  compiles every algorithm family, including those the product does not use.

No falsifier fired:
- Once the defects were fixed, nothing in the product needed editing.
- The stack was the production stack, with only the TLS edge and the container names changed.
- The time was under the bound on this machine.

Next: section 9 step 2, the script, run from a fresh clone on a clean Docker cache.

## Step 2: one command (2026-09-30)

`lab/strategy/006/try.sh` does step 1's commands in order and takes care of the three open items:
- it runs the stack as its own compose project (`polaris-try`), with `names.yml` resetting the
  container names;
- `polaris-create-operator.sh --target=docker-stack` now hashes the password inside the running
  app container, so the host needs no werkzeug;
- it trusts Caddy's local root for every request instead of switching TLS checks off.

Run from a clean checkout on the same laptop, with a stock python3 and `--no-cache` on the image
build, it printed `signature_valid: True` and `issuer_trusted: True` and exited 0 after 431
seconds:

| step | seconds |
|---|---|
| build, no cache | 397 |
| secrets | 2 |
| stack healthy | 23 |
| operator | 2 |
| issue and pack | under 1 |
| polaris-verify from PyPI | 6 |

The base images were already on the machine. A first run elsewhere also downloads them, so
network speed adds to the 397 seconds. `--down` removes the stack and its data, and leaves the
key in `polaris_web/secrets/`.

No falsifier fired:
- It is one command.
- Nothing in the product was edited to pass. The operator script's in-image hash is a
  deployment fix, not a demo flag.
- It took 7 minutes, against a bound of 15.

Next: section 9 step 3, a README line and the weekly stranger's-path routine pointed at it.

## Step 3: a machine nobody configured (2026-09-30)

The README's Run it section names the command, and `.github/workflows/one-command.yml` runs it
on every push to main, every night, and on a pull request that changes a path it exercises. That
workflow takes the place the plan gave the weekly stranger's-path routine: it runs the script
itself, from clean images, every night instead of once a week.

Its first run, on pull request #120 at 53816424, used GitHub's `ubuntu-latest` runner with no
layer cache, so the base images came over the network. `polaris-verify` 1.0.0rc4 from PyPI printed
`signature_valid: True` and `issuer_trusted: True` and exited 0, 439 seconds after the script
started; the whole job took 7 minutes 28 seconds.

This is still the author's run. The runner is a machine nobody configured by hand, not an operator
who is not the author, so the operating contract's open 1.0.0 condition is unchanged.

No falsifier fired:
- It is one command, on a machine the author never touched.
- Nothing in the product was edited to pass.
- It took 7 minutes 19 seconds, against a bound of 15.

Next: nothing in the tree. What 006 was for, an operator who is not the author reaching a verified
result without help, only that operator can supply.
