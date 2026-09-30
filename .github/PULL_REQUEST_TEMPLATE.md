## Motivation

<!-- The need this change answers. Link the issue or proposal. -->

## Change

<!-- What changed, in the order a reviewer should read it. -->

## Blast radius

<!-- Tables, routes, scripts, documents and checks touched; what an operator must do on upgrade; anything reopened from the roadmap. -->

## Constraints

<!-- Which of C1 to C10 this touches and how each stays enforced at the database level, or "none". -->

## Test discipline

- [ ] Every commit is signed off (`git commit -s`)
- [ ] The tests for what this touches pass, and new behaviour carries a test that fails without it (or a `check_*` with a detection test)
- [ ] `python3 -m polaris_checks.run` reports READY
- [ ] `./scripts/polaris-link-check.sh --ci` resolves every reference
- [ ] One CHANGELOG line under `## Unreleased` for anything externally observable, and no version bump
- [ ] Documentation that describes the changed behaviour is updated in this PR

<!-- The maintainer runs the database suites and the drills before merging. -->
