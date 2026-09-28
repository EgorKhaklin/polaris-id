# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Static reference data for the national simulation: the real United States as
a table of jurisdictions with populations, plus deterministic name pools.

The populations are the 2020 US Census apportionment counts (persons). They are
used only for PROPORTIONS: the simulation downscales by a factor, so the exact
figures do not need to be current, only realistically proportioned across the
states so that California carries far more synthetic activity than Wyoming.

Nothing here is random or time-dependent; the generator seeds its own PRNG.
"""

from __future__ import annotations

# ISO 3166-2 code (as stored in Individual.jurisdiction / Agency.jurisdiction),
# common name, and 2020 Census population. All 50 states + DC. Territories are
# omitted for now (they enroll through federal bureaus and add little to a
# proportional load); a later ship can add them.
US_STATES: list[tuple[str, str, int]] = [
    ("US-CA", "California", 39538223),
    ("US-TX", "Texas", 29145505),
    ("US-FL", "Florida", 21538187),
    ("US-NY", "New York", 20201249),
    ("US-PA", "Pennsylvania", 13002700),
    ("US-IL", "Illinois", 12812508),
    ("US-OH", "Ohio", 11799448),
    ("US-GA", "Georgia", 10711908),
    ("US-NC", "North Carolina", 10439388),
    ("US-MI", "Michigan", 10077331),
    ("US-NJ", "New Jersey", 9288994),
    ("US-VA", "Virginia", 8631393),
    ("US-WA", "Washington", 7705281),
    ("US-AZ", "Arizona", 7151502),
    ("US-MA", "Massachusetts", 7029917),
    ("US-TN", "Tennessee", 6910840),
    ("US-IN", "Indiana", 6785528),
    ("US-MD", "Maryland", 6177224),
    ("US-MO", "Missouri", 6154913),
    ("US-WI", "Wisconsin", 5893718),
    ("US-CO", "Colorado", 5773714),
    ("US-MN", "Minnesota", 5706494),
    ("US-SC", "South Carolina", 5118425),
    ("US-AL", "Alabama", 5024279),
    ("US-LA", "Louisiana", 4657757),
    ("US-KY", "Kentucky", 4505836),
    ("US-OR", "Oregon", 4237256),
    ("US-OK", "Oklahoma", 3959353),
    ("US-CT", "Connecticut", 3605944),
    ("US-UT", "Utah", 3271616),
    ("US-IA", "Iowa", 3190369),
    ("US-NV", "Nevada", 3104614),
    ("US-AR", "Arkansas", 3011524),
    ("US-MS", "Mississippi", 2961279),
    ("US-KS", "Kansas", 2937880),
    ("US-NM", "New Mexico", 2117522),
    ("US-NE", "Nebraska", 1961504),
    ("US-ID", "Idaho", 1839106),
    ("US-WV", "West Virginia", 1793716),
    ("US-HI", "Hawaii", 1455271),
    ("US-NH", "New Hampshire", 1377529),
    ("US-ME", "Maine", 1362359),
    ("US-RI", "Rhode Island", 1097379),
    ("US-MT", "Montana", 1084225),
    ("US-DE", "Delaware", 989948),
    ("US-SD", "South Dakota", 886667),
    ("US-ND", "North Dakota", 779094),
    ("US-AK", "Alaska", 733391),
    ("US-DC", "District of Columbia", 689545),
    ("US-VT", "Vermont", 643077),
    ("US-WY", "Wyoming", 576851),
]

US_TOTAL_POPULATION: int = sum(pop for _, _, pop in US_STATES)


# Approximate geographic centroid (lat, lon) per jurisdiction. A located
# verification is placed near its holder's state centroid with a little jitter,
# so the simulated activity falls where the population is, not on a single
# point. Approximate on purpose: this is notional geography for a density map,
# not a survey.
STATE_CENTROIDS: dict[str, tuple[float, float]] = {
    "US-AL": (32.8, -86.8), "US-AK": (64.0, -152.0), "US-AZ": (34.2, -111.7),
    "US-AR": (34.9, -92.4), "US-CA": (37.2, -119.3), "US-CO": (39.0, -105.5),
    "US-CT": (41.6, -72.7), "US-DE": (39.0, -75.5), "US-FL": (28.6, -82.4),
    "US-GA": (32.6, -83.4), "US-HI": (20.3, -156.4), "US-ID": (44.4, -114.6),
    "US-IL": (40.0, -89.2), "US-IN": (39.9, -86.3), "US-IA": (42.0, -93.5),
    "US-KS": (38.5, -98.4), "US-KY": (37.5, -85.3), "US-LA": (31.0, -92.0),
    "US-ME": (45.4, -69.2), "US-MD": (39.0, -76.8), "US-MA": (42.3, -71.8),
    "US-MI": (44.3, -85.4), "US-MN": (46.3, -94.3), "US-MS": (32.7, -89.7),
    "US-MO": (38.4, -92.5), "US-MT": (47.0, -109.6), "US-NE": (41.5, -99.8),
    "US-NV": (39.3, -116.6), "US-NH": (43.7, -71.6), "US-NJ": (40.2, -74.7),
    "US-NM": (34.4, -106.1), "US-NY": (42.9, -75.5), "US-NC": (35.6, -79.4),
    "US-ND": (47.5, -100.3), "US-OH": (40.3, -82.8), "US-OK": (35.6, -97.5),
    "US-OR": (44.0, -120.5), "US-PA": (40.9, -77.8), "US-RI": (41.7, -71.6),
    "US-SC": (33.9, -80.9), "US-SD": (44.4, -100.2), "US-TN": (35.9, -86.4),
    "US-TX": (31.5, -99.3), "US-UT": (39.3, -111.7), "US-VT": (44.0, -72.7),
    "US-VA": (37.5, -78.9), "US-WA": (47.4, -120.5), "US-WV": (38.6, -80.6),
    "US-WI": (44.6, -89.9), "US-WY": (43.0, -107.6), "US-DC": (38.9, -77.0),
}

# Name -> jurisdiction, for turning a jurisdiction code into a human location
# label on a located event.
STATE_NAMES: dict[str, str] = {code: name for code, name, _ in US_STATES}


# Deterministic name pools. Small on purpose: the generator combines first +
# last + a per-person disambiguator so a few dozen of each still yield unique,
# non-repeating legal names across millions of synthetic people.
FIRST_NAMES: tuple[str, ...] = (
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle",
    "Kenneth", "Carol", "Kevin", "Amanda", "Brian", "Dorothy", "George", "Melissa",
    "Timothy", "Deborah", "Ronald", "Stephanie", "Jason", "Rebecca", "Edward", "Sharon",
    "Jeffrey", "Laura", "Ryan", "Cynthia", "Jacob", "Amy", "Gary", "Kathleen",
    "Nicholas", "Angela", "Eric", "Shirley", "Jonathan", "Brenda", "Stephen", "Emma",
    "Larry", "Anna", "Justin", "Pamela", "Scott", "Nicole", "Brandon", "Samantha",
    "Benjamin", "Katherine", "Samuel", "Christine", "Gregory", "Helen", "Alexander", "Debra",
    "Patrick", "Rachel", "Frank", "Carolyn", "Raymond", "Janet", "Jack", "Maria",
    "Dennis", "Catherine", "Jerry", "Heather", "Aaron", "Diane", "Jose", "Olivia",
)

LAST_NAMES: tuple[str, ...] = (
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
    "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
    "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young",
    "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker",
    "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", "Murphy",
    "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey",
    "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson",
    "Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza",
    "Ruiz", "Hughes", "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers",
    "Long", "Ross", "Foster", "Jimenez", "Powell", "Jenkins", "Perry", "Russell",
)


def scaled_population(scale_divisor: int) -> list[tuple[str, str, int]]:
    """Return (iso_code, name, synthetic_person_count) per state for a downscale
    factor. Every state keeps at least one synthetic person so the whole nation
    is represented even at a small scale; larger states keep their proportion.
    """
    if scale_divisor < 1:
        raise ValueError("scale_divisor must be >= 1")
    out: list[tuple[str, str, int]] = []
    for code, name, pop in US_STATES:
        n = max(1, pop // scale_divisor)
        out.append((code, name, n))
    return out
