# Governance

How decisions about Polaris are made, who does what, and how the project continues if its
maintainer cannot.

## Model

Polaris has one maintainer, Egor Khaklin, who makes the final decision on every change. Decisions
are not made by preference. They are made against these documents, stronger first:

1. [MISSION.md](MISSION.md), the constitution. It is amended only by a recorded decision of the
   maintainer, logged in the changelog.
2. The [operating contract](docs/OPERATING-CONTRACT.md): what work qualifies at all, and what a
   version means.
3. The published contracts: [SECURITY.md](SECURITY.md), the wire and API references, the
   conformance suite, and the packages on the registries.
4. The machine-enforced checks, which fail the build when a guarantee stops holding. A check is
   never loosened to let a change through.

Anyone can propose a change: small fixes by issue or pull request, larger ones by a change proposal
([CONTRIBUTING.md](CONTRIBUTING.md)). A change merges when it meets the rules there and the gate
passes.

## Roles

| Role | Who | Responsibilities |
|---|---|---|
| Maintainer | Egor Khaklin | Reviews and merges changes, through pull requests like everyone else; cuts releases; publishes the packages (npm releases need the maintainer's second factor); answers security reports under [SECURITY.md](SECURITY.md); holds the project's accounts |
| Contributor | anyone | Proposes changes through issues and pull requests, signed off under the Developer Certificate of Origin |
| Security reporter | anyone | Reports privately as [SECURITY.md](SECURITY.md) describes; credited unless they ask not to be |

A contributor who sustains substantial, reviewed contributions can be invited to become a second
maintainer, with the same access and responsibilities.

## Access and review

Before anyone is given write access to the repository or ownership of a published package, the
maintainer reviews their contributions to the project (sustained work that went through review),
confirms that their account uses two-factor authentication, and grants the least access the role
needs. Access is removed when the role ends.

Every change reaches `main` through a pull request. Review checks that the change carries a test
that fails without it, that the gate and the required checks pass, that no constraint in
[MISSION.md](MISSION.md) is weakened, that every commit is signed off, and that any changelog line is
short and accurate. While Polaris has one maintainer, the reviewer is the author; approval by a
person other than the author becomes a rule once there is a second maintainer.

## Continuity

The maintainer keeps what is needed to continue the project (the GitHub repository, the PyPI and
npm package ownership, and the project site) with a designated trusted person, together with
written permission to continue the project. If the maintainer is unable to continue, that person
can create and close issues, accept changes and publish releases within a week.

The bus factor is one today. What lowers the cost of a handover: the documentation, the gate that
reproduces CI locally, and the checks that fail when a guarantee stops holding.
