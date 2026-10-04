"""Region plugins with fake entry points: nothing needs to be installed."""
import unittest
from unittest import mock

from text_sanitizer_core import Region, build, load_regions

DOC_A = Region("aa", masks=[("doc_a", r"\bAA-\d{6}\b", "<DOC_A>")])
DOC_B = Region("bb", masks=[("doc_b", r"\bBB-\d{6}\b", "<DOC_B>")], ner_model="modelo_que_nao_existe")


class FakeEP:
    def __init__(self, name, value=None, error=None):
        self.name, self._value, self._error = name, value, error

    def load(self):
        if self._error:
            raise self._error
        return self._value


def installed(*eps):
    return mock.patch("text_sanitizer_core.plugins.entry_points", lambda group: list(eps))


class Build(unittest.TestCase):
    def test_regions_combine_in_one_pass(self):
        with installed(FakeEP("aa", DOC_A), FakeEP("bb", DOC_B)):
            clean, report = build(["aa", "bb"]).sanitize("AA-123456 BB-654321 fulano@example.com")
        self.assertEqual(clean, "<DOC_A> <DOC_B> <EMAIL>")
        self.assertTrue(report.ok)

    def test_empty_list_is_core_only(self):
        with installed():
            clean, report = build([]).sanitize("AA-123456 fulano@example.com")
        self.assertEqual(clean, "AA-<N> <EMAIL>")  # no region: only the core rules
        self.assertTrue(report.ok)

    def test_missing_region_blocks(self):
        with installed(FakeEP("aa", DOC_A)):
            clean, report = build(["aa", "eu"]).sanitize("texto")
        self.assertEqual(clean, "")
        self.assertEqual(report.blocked, ["region_missing:eu"])

    def test_broken_or_invalid_region_blocks(self):
        with installed(FakeEP("aa", error=ImportError()), FakeEP("bb", value="not a Region")):
            _, errors = load_regions(["aa", "bb"])
        self.assertEqual(errors, ["region_failed:aa:ImportError", "region_invalid:bb"])

    def test_ner_needs_a_region_model(self):
        with installed(FakeEP("aa", DOC_A)):
            self.assertEqual(build(["aa"], ner=True).sanitize("x")[1].blocked, ["ner_unavailable:no_region_model"])

    def test_ner_with_missing_model_blocks(self):
        with installed(FakeEP("bb", DOC_B)):
            blocked = build(["bb"], ner=True).sanitize("x")[1].blocked
        self.assertTrue(blocked[0].startswith("ner_unavailable"), blocked)


if __name__ == "__main__":
    unittest.main()
