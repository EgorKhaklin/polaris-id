# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lookup.py: find one record by what an operator holds, at any population.

Decision record: lab/strategy/008-population-scale.md. Seven operation forms listed every active
credential or every person in a dropdown: a page that grows with the population, and that no
browser renders at eight billion. A form now starts from one record, found through a unique
index by what the operator has in hand:

- a credential by its number (#1234), its token value or its card serial. Three unique indexes,
  so at most three rows; more than one only when a number, a value and a serial written the same
  way belong to different credentials, which the page shows as a choice rather than guessing.
- a person by number, or by date of birth and the beginning of the name as recorded, through
  idx_individual_birth_name, at most LOOKUP_LIMIT rows. A name alone is not a lookup: without
  the date it would page through everyone who shares a name.

Row-level security applies as it does to every read: an operator bound to one authority does
not find a credential another authority issued, and is told exactly what a credential that does
not exist would tell them, so the lookup is not an oracle for another authority's records.

What the operator typed never reaches a URL. It travels in a POST body (the relying-party API
keeps identifiers out of URLs the same way), and the page it leads to names the record by its
number. Every reader takes the application's query function first, as population.py does, so
this module imports nothing from the application.
"""
import re

#: The most people one name search shows. One more is read, to say that there are more.
LOOKUP_LIMIT = 20

#: The largest number a key can hold. A larger one is no record's number, and is not sent to the
#: database: a literal past BIGINT is NUMERIC, and comparing a key with a NUMERIC cannot use the
#: key's index.
MAX_KEY = 2 ** 63 - 1

#: The longest text a credential lookup compares: token_value is VARCHAR(128) (physical_serial is
#: 64), so anything longer matches nothing and is not sent.
MAX_CREDENTIAL_TEXT = 128

#: The longest name prefix a person lookup compares (legal_name is VARCHAR(200)).
MAX_NAME_TEXT = 200

_DIGITS = re.compile(r'[0-9]{1,19}', re.ASCII)

#: The longest text read as a number: '#', a space and nineteen digits, with room to spare. Longer
#: text is no number, and is not scanned (a URL parameter can be any length).
MAX_NUMBER_TEXT = 32


def number(text):
    """The record number written in `text` ('1234' or '#1234'), or None. ASCII digits only:
    Python's int() also reads other scripts' digits, and a number nobody typed as digits is
    not a number the operator meant."""
    if text is None:
        return None
    if isinstance(text, int) and not isinstance(text, bool):
        return text if 0 < text <= MAX_KEY else None
    s = str(text)
    if len(s) > MAX_NUMBER_TEXT:
        return None
    s = s.strip()
    if s.startswith('#'):
        s = s[1:].lstrip()
    if not _DIGITS.fullmatch(s):
        return None
    n = int(s)
    return n if 0 < n <= MAX_KEY else None


_CREDENTIAL = """
    SELECT t.token_id, t.token_value, t.physical_serial, t.status, t.issued_date,
           t.activated_date, t.expiration_date, t.individual_id, t.issuing_agency_id,
           t.algorithm_id, i.legal_name, i.date_of_birth, i.jurisdiction,
           ag.name AS issuer_name, alg.name AS algorithm_name, alg.quantum_resistant,
           (t.expiration_date IS NOT NULL AND t.expiration_date < polaris_utc_date())
               AS past_expiry
      FROM IdentityToken t
      JOIN Individual i ON i.individual_id = t.individual_id
      JOIN Agency ag ON ag.agency_id = t.issuing_agency_id
      JOIN CryptographicAlgorithm alg ON alg.algorithm_id = t.algorithm_id
"""


def credential(query, token_id):
    """One credential by its number, with its holder, issuer and algorithm; None when there is
    no such credential or this operator may not see it (the two read the same)."""
    n = number(token_id)
    if n is None:
        return None
    return query(_CREDENTIAL + ' WHERE t.token_id = %s', (n,), fetch='one')


def credentials(query, text):
    """Every credential whose number, token value or card serial is `text`, in number order: at
    most three, each read through its own unique index (three lookups rather than one OR, so no
    plan has to combine indexes to stay bounded)."""
    text = (text or '').strip()
    if not text or len(text) > MAX_CREDENTIAL_TEXT:
        return []
    found = {}
    for column, value in (('t.token_value', text), ('t.physical_serial', text),
                          ('t.token_id', number(text))):
        if value is None:
            continue
        row = query(_CREDENTIAL + ' WHERE ' + column + ' = %s', (value,), fetch='one')
        if row:
            found[row['token_id']] = row
    return [found[k] for k in sorted(found)]


_PERSON = """
    SELECT i.individual_id, i.legal_name, i.date_of_birth, i.jurisdiction, i.enrollment_date
      FROM Individual i
"""


def person(query, individual_id):
    """One person by number, or None."""
    n = number(individual_id)
    if n is None:
        return None
    return query(_PERSON + ' WHERE i.individual_id = %s', (n,), fetch='one')


def _like_prefix(text):
    """`text` as a LIKE pattern that matches it as a prefix, its wildcards escaped."""
    return re.sub(r'([\\%_])', r'\\\1', text) + '%'


def people(query, text, born=None):
    """(rows, more): the person numbered `text`, or the people born on `born` whose recorded
    name begins with `text`, ignoring case, in name order; `more` is true when there are more
    than LOOKUP_LIMIT. A name without a date finds nobody: see the module docstring.

    The order is the index's own (the lowercased name under the C collation, then the number),
    so the database stops after LOOKUP_LIMIT + 1 rows however many share the date."""
    text = ' '.join((text or '').split())
    n = number(text)
    if n is not None:
        row = person(query, n)
        return ([row] if row else []), False
    if not text or born is None or len(text) > MAX_NAME_TEXT:
        return [], False
    rows = query(_PERSON + """
         WHERE i.date_of_birth = %(born)s
           AND lower(i.legal_name) COLLATE "C" LIKE lower(%(prefix)s) ESCAPE '\\'
         ORDER BY lower(i.legal_name) COLLATE "C", i.individual_id
         LIMIT %(limit)s
    """, {'born': born, 'prefix': _like_prefix(text), 'limit': LOOKUP_LIMIT + 1})
    return rows[:LOOKUP_LIMIT], len(rows) > LOOKUP_LIMIT


def chosen_credential(query, raw):
    """(credential, missing) for a page that acts on the credential numbered `raw`, a URL or form
    field: the credential, or else what was asked for and not found: its number, or '?' for text
    that is no number. (None, None) when nothing was named."""
    if raw is None or str(raw).strip() == '':
        return None, None
    found = credential(query, raw)
    return (found, None) if found else (None, number(raw) or '?')


def chosen_person(query, raw):
    """(person, missing), as chosen_credential for a person."""
    if raw is None or str(raw).strip() == '':
        return None, None
    found = person(query, raw)
    return (found, None) if found else (None, number(raw) or '?')
