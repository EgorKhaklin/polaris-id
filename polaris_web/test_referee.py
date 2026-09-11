"""test_referee.py - the trusted referee (roadmap P4.4).

The referee path is the anti-exclusion mechanism in enrollment and the most obvious forgery
channel in it, and they are the same table. These tests are mostly about the second thing,
because the first thing is why it cannot simply be refused.

Run: python3 -m unittest test_referee
"""

import os
import unittest

from referee import (
    MINIMUM_REFEREE_IAL, RELATIONSHIPS, VOUCHING_BOUND, VOUCHING_CEILING,
    VouchingRefused, check_vouching, vouching_ceiling, why_refused,
)

SCHEMA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "polaris_sql", "01_schema.sql")


def vouching(**over):
    base = dict(referee_id=1, applicant_id=2, referee_ial="IAL2",
                relationship="SOCIAL_WORKER", vouched_ial="IAL2")
    base.update(over)
    return base


class CeilingTests(unittest.TestCase):

    def test_a_referee_at_ial3_is_still_capped_at_ial2(self):
        """The ceiling is about what a third party can establish, not how well the
        referee was proofed. IAL3 needs the APPLICANT's live biometric."""
        self.assertEqual(vouching_ceiling("IAL3"), "IAL2")
        self.assertEqual(VOUCHING_CEILING, "IAL2")

    def test_a_referee_at_ial2_vouches_at_ial2(self):
        self.assertEqual(vouching_ceiling("IAL2"), "IAL2")

    def test_a_referee_at_ial1_cannot_vouch_at_all(self):
        """An unproofed person vouching for an unproofed person is two strangers
        agreeing."""
        self.assertIsNone(vouching_ceiling("IAL1"))
        self.assertEqual(MINIMUM_REFEREE_IAL, "IAL2")

    def test_an_unknown_level_is_refused_not_defaulted(self):
        with self.assertRaises(VouchingRefused):
            vouching_ceiling("IAL9")


class RefusalTests(unittest.TestCase):
    """Each refusal names what is wrong, because one that does not sends the operator
    back to re-run the identical session."""

    def refusal(self, **over):
        with self.assertRaises(VouchingRefused) as caught:
            check_vouching(**vouching(**over))
        return str(caught.exception)

    def test_a_well_formed_vouching_stands(self):
        self.assertEqual(check_vouching(**vouching()), "IAL2")

    def test_nobody_vouches_for_themselves(self):
        self.assertIn("cannot vouch for themselves", self.refusal(applicant_id=1))

    def test_the_co_signer_is_a_third_person(self):
        """Past the bound the point is a second pair of eyes, and the referee's own
        are already on it."""
        msg = self.refusal(co_signer_id=1)
        self.assertIn("third person", msg)
        self.assertIn("third person", self.refusal(co_signer_id=2))

    def test_the_relationship_vocabulary_is_closed(self):
        """'Knows the applicant' covers a caseworker and a stranger paid fifty pounds."""
        msg = self.refusal(relationship="A FRIEND")
        self.assertIn("closed", msg)
        for known in RELATIONSHIPS:
            self.assertEqual(check_vouching(**vouching(relationship=known)), "IAL2")

    def test_no_vouching_reaches_ial3_however_proofed_the_referee(self):
        msg = self.refusal(referee_ial="IAL3", vouched_ial="IAL3")
        self.assertIn("no vouching reaches IAL3", msg)
        self.assertIn("cannot be their face", msg)

    def test_a_referee_cannot_vouch_above_their_own_level(self):
        msg = self.refusal(referee_ial="IAL1", vouched_ial="IAL2")
        self.assertIn("cannot vouch", msg)

    def test_a_referee_may_vouch_below_their_own_level(self):
        """An underclaim is allowed here for the same reason it is in proofing: an
        authority may hold itself to less than it could assert."""
        self.assertEqual(check_vouching(**vouching(referee_ial="IAL3",
                                                   vouched_ial="IAL1")), "IAL1")


class BoundTests(unittest.TestCase):
    """The bound asks for a co-signer. It never refuses."""

    def test_below_the_bound_no_co_signer_is_needed(self):
        self.assertEqual(
            check_vouching(**vouching(vouchings_in_window=VOUCHING_BOUND - 1)), "IAL2")

    def test_at_the_bound_a_co_signer_is_required(self):
        with self.assertRaises(VouchingRefused) as caught:
            check_vouching(**vouching(vouchings_in_window=VOUCHING_BOUND))
        self.assertIn("CO-SIGNER", str(caught.exception))

    def test_the_refusal_says_it_is_not_a_refusal(self):
        """A caseworker with a heavy month and a compromised referee look identical
        from here, and refusing would break the first to catch the second."""
        with self.assertRaises(VouchingRefused) as caught:
            check_vouching(**vouching(vouchings_in_window=VOUCHING_BOUND + 100))
        msg = str(caught.exception)
        self.assertIn("not a refusal", msg)
        self.assertIn("would break the first to catch the second", msg)

    def test_a_co_signer_lifts_the_bound_at_any_volume(self):
        self.assertEqual(
            check_vouching(**vouching(vouchings_in_window=10_000, co_signer_id=99)),
            "IAL2")

    def test_the_bound_is_tunable_per_deployment(self):
        with self.assertRaises(VouchingRefused):
            check_vouching(**vouching(vouchings_in_window=3, bound=3))
        self.assertEqual(check_vouching(**vouching(vouchings_in_window=3, bound=50)),
                         "IAL2")


class ExplanationTests(unittest.TestCase):

    def test_why_refused_returns_the_sentence(self):
        self.assertIn("themselves", why_refused(**vouching(applicant_id=1)))

    def test_why_refused_confirms_a_vouching_that_stands(self):
        self.assertEqual(why_refused(**vouching()), "the vouching stands at IAL2")


class SchemaTests(unittest.TestCase):
    """The floors are in the database, and one thing is deliberately absent from it."""

    def setUp(self):
        with open(SCHEMA) as fh:
            self.schema = fh.read()
        start = self.schema.index("CREATE TABLE IF NOT EXISTS RefereeVouching")
        self.table = self.schema[start:self.schema.index("\n);", start)]

    def test_the_database_holds_every_floor_the_module_checks(self):
        for constraint in ("referee_is_not_the_applicant", "co_signer_is_a_third_person",
                           "cannot_vouch_above_own_level", "vouching_never_reaches_ial3"):
            self.assertIn(constraint, self.table,
                          f"{constraint} must be a database floor, not only a module check")

    def test_the_surrogate_id_is_64_bit(self):
        """v9.384's lesson: a table added after it does not repeat it."""
        self.assertIn("vouching_id             BIGSERIAL", self.table)

    def test_the_referee_level_is_copied_not_joined(self):
        """A referee re-proofed downward later must not silently rewrite what this
        vouching was worth when it was made."""
        self.assertIn("referee_ial", self.table)

    def test_no_vouching_reaches_the_credential(self):
        """THE DIGNITY PROPERTY, and it is an absence rather than a rule.

        A credential asserts an assurance LEVEL and never the circumstances its holder
        was in when they got it. If IdentityToken ever gained a reference to a vouching,
        a person who needed a referee would be carrying a mark for it at every counter.
        """
        token_start = self.schema.index("CREATE TABLE IdentityToken")
        token = self.schema[token_start:self.schema.index("\n);", token_start)]
        for leak in ("vouching", "referee", "RefereeVouching"):
            self.assertNotIn(leak.lower(), token.lower(),
                             "IdentityToken must carry no trace of a vouching")

    def test_the_compromise_query_has_an_index(self):
        """A referee found to have vouched falsely makes every credential they touched
        a question, and an authority that cannot enumerate them cannot answer it."""
        self.assertIn("idx_vouching_by_referee", self.schema)


if __name__ == "__main__":
    unittest.main()
