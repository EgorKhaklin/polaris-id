"""test_enrollment_code.py - the secret sent to a channel (roadmap P4.4).

What a code establishes is narrow: somebody who could reach that channel returned the secret.
Not that they are the applicant. These tests are about the lifecycle that keeps it that narrow
-- short validity, single use, a bound that actually counts, and a plaintext that exists in one
place for one moment.

Run: python3 -m unittest test_enrollment_code
"""

import os
import unittest

from enrollment_code import (
    CHANNELS, CODE_ENTROPY_BYTES, MAX_ATTEMPTS, MAX_VALIDITY_DAYS,
    CodeRefused, generate_code, hash_code,
)

SCHEMA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "polaris_sql", "01_schema.sql")


class CodeTests(unittest.TestCase):

    def test_a_code_carries_real_entropy(self):
        self.assertGreaterEqual(CODE_ENTROPY_BYTES * 8, 128)

    def test_two_codes_are_not_the_same_code(self):
        self.assertNotEqual(generate_code()[0], generate_code()[0])

    def test_the_hash_is_sha256_hex_and_matches_the_schema_constraint(self):
        import re
        _, digest = generate_code()
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        with open(SCHEMA) as fh:
            self.assertIn("code_hash_is_sha256_hex", fh.read())
        self.assertIsNotNone(re.match(r"^[0-9a-f]{64}$", digest))

    def test_a_code_typed_back_in_groups_still_matches(self):
        """It is read off a letter or a screen and typed back by a person.

        Normalising before hashing keeps the comparison single-path: there is no
        second, sloppier route that a near-miss falls into.
        """
        code, digest = generate_code()
        for typed in (code.lower(), code.replace("-", " "), code.replace("-", ""),
                      "  " + code.lower().replace("-", "  ") + " "):
            self.assertEqual(hash_code(typed), digest, f"{typed!r} should match")

    def test_an_empty_code_is_refused_rather_than_hashed(self):
        for empty in ("", "   ", "--", " - - "):
            with self.assertRaises(CodeRefused):
                hash_code(empty)

    def test_a_different_code_hashes_differently(self):
        self.assertNotEqual(hash_code("AAAA-BBBB"), hash_code("AAAA-BBBC"))


class BoundTests(unittest.TestCase):

    def test_validity_is_capped(self):
        self.assertLessEqual(MAX_VALIDITY_DAYS, 30)

    def test_the_attempt_bound_is_small(self):
        self.assertLessEqual(MAX_ATTEMPTS, 10)

    def test_the_channel_vocabulary_is_closed(self):
        self.assertIn("POSTAL", CHANNELS)
        self.assertIn("IN_PERSON_HANDOVER", CHANNELS)


class SchemaTests(unittest.TestCase):
    """The floors are in the database, and one column is deliberately absent."""

    def setUp(self):
        with open(SCHEMA) as fh:
            self.schema = fh.read()
        start = self.schema.index("CREATE TABLE IF NOT EXISTS EnrollmentCode")
        self.table = self.schema[start:self.schema.index("\n);", start)]

    def test_the_database_holds_the_lifecycle_floors(self):
        for constraint in ("code_hash_is_sha256_hex", "expires_after_it_is_issued",
                           "validity_is_bounded", "redeemed_inside_its_validity",
                           "attempts_are_bounded", "a_redeemed_code_names_its_proofing"):
            self.assertIn(constraint, self.table,
                          f"{constraint} must be a database floor, not only a module check")

    def test_there_is_no_column_for_the_code_itself(self):
        """THE ABSENCE. A leaked enrollment database should be a pile of hashes.

        A column that COULD hold a plaintext code is a column somebody eventually
        writes one into.
        """
        for leak in ("code_plain", "code_value", "secret", "plaintext"):
            self.assertNotIn(leak, self.table.lower())
        self.assertIn("code_hash", self.table)

    def test_the_module_and_the_schema_agree_on_the_attempt_bound(self):
        self.assertIn("attempts <= %d" % MAX_ATTEMPTS, self.table)

    def test_the_module_and_the_schema_agree_on_validity(self):
        self.assertIn("INTERVAL '%d days'" % MAX_VALIDITY_DAYS, self.table)

    def test_the_surrogate_id_is_64_bit(self):
        self.assertIn("code_id             BIGSERIAL", self.table)


class OneWayDoorTests(unittest.TestCase):
    """A code is live state, not an audit record, so it has a door rather than a wall."""

    def setUp(self):
        triggers = os.path.join(os.path.dirname(SCHEMA), "06_triggers.sql")
        with open(triggers) as fh:
            self.triggers = fh.read()

    def test_the_trigger_exists_and_is_not_the_append_only_one(self):
        self.assertIn("enrollment_code_one_way_door", self.triggers)
        self.assertIn("BEFORE UPDATE ON EnrollmentCode", self.triggers)
        self.assertNotIn("BEFORE UPDATE OR DELETE ON EnrollmentCode", self.triggers,
                         "an append-only rule would make redemption itself impossible")

    def test_it_pins_what_cannot_change(self):
        door = self.triggers[self.triggers.index("enrollment_code_one_way_door"):]
        for immutable in ("code_hash", "individual_id", "channel", "issued_at", "expires_at"):
            self.assertIn(immutable, door)

    def test_it_refuses_a_second_redemption_and_a_lowered_counter(self):
        door = self.triggers[self.triggers.index("enrollment_code_one_way_door"):]
        self.assertIn("single use", door)
        self.assertIn("cannot be lowered", door)


if __name__ == "__main__":
    unittest.main()
