# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Deterministic generator of a synthetic United States: ID bureaus in every
state, scaled by population, and the people they enroll.

Everything here is a pure function of (scale_divisor, seed). No wall-clock, no
global RNG: a plan is reproducible, and two plans with the same inputs are
byte-for-byte identical, which is what makes a benchmark comparable. People are
produced as a stream (per agency) so the generator holds only one bureau's batch
in memory at a time and scales to the full nation.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import random
from dataclasses import dataclass
from typing import Iterator

from . import reference


# One synthetic ID bureau. jurisdiction is the ISO 3166-2 state code; these map
# directly onto Agency.jurisdiction / Individual.jurisdiction.
@dataclass(frozen=True)
class Bureau:
    name: str
    agency_type: str          # FEDERAL | STATE | COUNTY | MUNICIPAL
    jurisdiction: str
    authorization_level: int
    enroll_count: int         # how many synthetic people this bureau enrolls


@dataclass(frozen=True)
class NationPlan:
    scale_divisor: int
    seed: int
    bureaus: tuple[Bureau, ...]

    @property
    def total_people(self) -> int:
        return sum(b.enroll_count for b in self.bureaus)

    @property
    def total_bureaus(self) -> int:
        return len(self.bureaus)

    @property
    def jurisdictions(self) -> int:
        return len({b.jurisdiction for b in self.bureaus})


# One state-level office per state, plus one extra county/municipal bureau per
# this many people, so a big state gets many bureaus and a small one gets a few.
_PEOPLE_PER_LOCAL_BUREAU = 750_000
_MAX_LOCAL_BUREAUS_PER_STATE = 40      # keep a single state's bureau list bounded

_COUNTY_SUFFIXES = (
    "Central", "Northern", "Southern", "Eastern", "Western", "Coastal", "Valley",
    "Highland", "Lakeside", "Riverside", "Metro", "Capital", "Bay", "Delta",
    "Piedmont", "Gateway", "Summit", "Harbor", "Prairie", "Frontier",
)


def _derived_seed(*parts: object) -> int:
    """A stable integer seed derived from the base seed plus identifying parts,
    so each bureau's people stream is independent yet reproducible."""
    h = hashlib.sha256("|".join(str(p) for p in parts).encode()).digest()
    return int.from_bytes(h[:8], "big")


def plan_nation(scale_divisor: int, seed: int) -> NationPlan:
    """Build the (small, in-memory) plan: every bureau in the nation and how many
    people it enrolls. People themselves are streamed later, per bureau."""
    if scale_divisor < 1:
        raise ValueError("scale_divisor must be >= 1")
    rng = random.Random(_derived_seed(seed, "bureaus"))
    bureaus: list[Bureau] = []

    # One federal bureau in the District of Columbia, the highest authorization.
    bureaus.append(Bureau("Federal Identity Service", "FEDERAL", "US-DC", 5, 0))

    for code, name, pop in reference.scaled_population(scale_divisor):
        # The number of LOCAL bureaus tracks this state's real population, not
        # its downscaled headcount, so every state keeps a realistic bureau
        # footprint even at a small scale.
        real_pop = next(p for c, _, p in reference.US_STATES if c == code)
        n_local = max(1, min(_MAX_LOCAL_BUREAUS_PER_STATE,
                             real_pop // _PEOPLE_PER_LOCAL_BUREAU))

        # A state office (STATE), then n_local county/municipal bureaus.
        state_bureaus = [Bureau(f"{name} Identity Office", "STATE", code,
                                rng.randint(3, 4), 0)]
        for i in range(n_local):
            suffix = _COUNTY_SUFFIXES[i % len(_COUNTY_SUFFIXES)]
            # Disambiguate when the suffix pool wraps, so bureau names are unique
            # within a state even past 20 local bureaus.
            wrap = i // len(_COUNTY_SUFFIXES)
            bname = (f"{name} {suffix} Identity Bureau"
                     if wrap == 0 else f"{name} {suffix} Identity Bureau {wrap + 1}")
            tier = "COUNTY" if i % 2 == 0 else "MUNICIPAL"
            lvl = 2 if tier == "COUNTY" else 1
            state_bureaus.append(Bureau(bname, tier, code, lvl, 0))

        # Split this state's people across its bureaus. The state office takes a
        # larger share; the rest divide the remainder. Integer split with the
        # remainder handed to the state office so the totals are exact.
        people = pop
        weights = [3.0] + [1.0] * n_local          # state office weighted x3
        wsum = sum(weights)
        counts = [int(people * w / wsum) for w in weights]
        counts[0] += people - sum(counts)          # exact reconciliation
        for b, c in zip(state_bureaus, counts):
            bureaus.append(Bureau(b.name, b.agency_type, b.jurisdiction,
                                  b.authorization_level, c))

    return NationPlan(scale_divisor=scale_divisor, seed=seed, bureaus=tuple(bureaus))


# A synthetic person, ready to stage for enrollment.
@dataclass(frozen=True)
class Person:
    legal_name: str
    date_of_birth: _dt.date
    jurisdiction: str


# Adult age band. A rough, deterministic distribution skewed toward working age;
# realism can deepen in a later ship.
_MIN_AGE, _MAX_AGE = 18, 92
_TODAY = _dt.date(2026, 9, 6)


def generate_people(bureau: Bureau, seed: int) -> Iterator[Person]:
    """Stream this bureau's synthetic enrollees deterministically. Names may
    repeat across the nation exactly as real names do (no UNIQUE on legal_name);
    each person is a distinct individual regardless."""
    rng = random.Random(_derived_seed(seed, "people", bureau.jurisdiction, bureau.name))
    fn, ln = reference.FIRST_NAMES, reference.LAST_NAMES
    for _ in range(bureau.enroll_count):
        name = f"{fn[rng.randrange(len(fn))]} {ln[rng.randrange(len(ln))]}"
        # Triangular toward ~40 gives a plausible adult skew without a full pyramid.
        age = int(rng.triangular(_MIN_AGE, _MAX_AGE, 38))
        # Spread birthdays across the year deterministically.
        birth_year = _TODAY.year - age
        day_of_year = rng.randint(0, 364)
        dob = _dt.date(birth_year, 1, 1) + _dt.timedelta(days=day_of_year)
        yield Person(legal_name=name, date_of_birth=dob, jurisdiction=bureau.jurisdiction)
