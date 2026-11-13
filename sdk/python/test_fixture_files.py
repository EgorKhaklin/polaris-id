"""Guards test_sdk.py: a file opened for reading outside a `with` block is never closed,
and each one prints a ResourceWarning. Kept apart from test_sdk.py so it reads that file
from disk without depending on the SDK tests themselves."""
import os
import re
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_OPEN = re.compile(r"(?<![\w.])open\(")
_WRITE_MODE = re.compile(r"""['"][wax]b?['"]\)""")


class TestFixtureFilesAreClosed(unittest.TestCase):
    def test_no_fixture_is_read_without_closing_its_file(self):
        with open(os.path.join(_HERE, "test_sdk.py"), encoding="utf-8") as f:
            lines = f.read().splitlines()
        # A read-mode open() must sit on a `with` line; `f = open(...)` followed by a later read is caught too.
        leaked = [n for n, line in enumerate(lines, 1)
                  if _OPEN.search(line) and "with " not in line and not _WRITE_MODE.search(line)]
        self.assertEqual(leaked, [], "fixture files left open at test_sdk.py lines %s" % leaked)


if __name__ == "__main__":
    unittest.main()
