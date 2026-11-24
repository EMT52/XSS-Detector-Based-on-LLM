import copy
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from models import output_model


def run_results(vulnerable=None, safe=None, duration=1):
    return {
        "vulnerable_files": vulnerable or {},
        "safe_files": safe or {},
        "cant_parse_files": [],
        "testing_duration": duration,
    }


class SaveOutputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "output" / "results.json"

    def save(self, results):
        with redirect_stdout(StringIO()):
            output_model.save_output(results, self.output)

    def test_next_run_replaces_records_and_duration_and_archives_previous(self):
        first = run_results(vulnerable={"old-app/1": {"method": "standard"}}, duration=15)
        second = run_results(safe={"new-app/2": {"test_count": 0}}, duration=2)
        self.save(first)
        first_bytes = self.output.read_bytes()
        self.save(second)
        self.assertEqual(json.loads(self.output.read_text()), second)
        history = list((self.output.parent / "history").glob("*.json"))
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].read_bytes(), first_bytes)

    def test_retested_path_can_change_classification_in_either_direction(self):
        finding = run_results(vulnerable={"app/1": {"method": "standard"}})
        no_finding = run_results(safe={"app/1": {"test_count": 2}})
        for expected in (finding, no_finding, finding):
            self.save(expected)
            self.assertEqual(json.loads(self.output.read_text()), expected)

    def test_duplicate_categories_are_disjoint_without_mutating_caller(self):
        results = run_results(vulnerable={"app/1": {}}, safe={"app/1": {}, "app/2": {}})
        results["cant_parse_files"] = ["app/1", "app/2", "app/3", "app/3"]
        original = copy.deepcopy(results)
        self.save(results)
        saved = json.loads(self.output.read_text())
        self.assertEqual(saved["safe_files"], {"app/2": {}})
        self.assertEqual(saved["cant_parse_files"], ["app/3"])
        self.assertEqual(results, original)

    def test_corrupt_old_json_is_archived_without_blocking_new_run(self):
        self.output.parent.mkdir()
        old = b'{"interrupted":'
        self.output.write_bytes(old)
        expected = run_results(safe={"新项目/1": {"note": "未完成"}})
        self.save(expected)
        self.assertEqual(json.loads(self.output.read_text()), expected)
        archived = next((self.output.parent / "history").glob("*.json"))
        self.assertEqual(archived.read_bytes(), old)

    def test_failed_replace_keeps_previous_json_and_cleans_temporary_file(self):
        self.save(run_results(duration=8))
        before = self.output.read_bytes()
        with patch.object(output_model.os, "replace", side_effect=OSError("disk error")):
            with self.assertRaisesRegex(OSError, "disk error"):
                self.save(run_results(duration=3))
        self.assertEqual(self.output.read_bytes(), before)
        self.assertEqual(list(self.output.parent.glob("*.tmp")), [])

    def test_serialization_error_keeps_previous_output(self):
        self.save(run_results())
        before = self.output.read_bytes()
        invalid = run_results(safe={"app/1": {"bad": object()}})
        with self.assertRaises(TypeError):
            self.save(invalid)
        self.assertEqual(self.output.read_bytes(), before)


class LLMResultTests(unittest.TestCase):
    def setUp(self):
        self.path = "app/2/index.php"
        self.standard = {"test_count": 3, "note": "standard stage finished"}
        self.results = run_results(safe={self.path: copy.deepcopy(self.standard)})

    def record(self, result, **kwargs):
        return output_model.record_llm_result(
            self.results, self.path, result, "deepseek", **kwargs
        )

    def test_zero_payloads_are_not_marked_tested(self):
        self.record({"vulnerability_found": False, "custom_payloads_generated": 0,
                     "custom_payloads_tested": 0})
        entry = self.results["safe_files"][self.path]
        self.assertFalse(entry["llm_tested"])
        self.assertEqual(entry["status"], "inconclusive")
        self.assertEqual(entry["llm_details"]["status"], "not_tested")
        self.assertEqual(entry["standard_result"], self.standard)

    def test_llm_error_and_standard_error_both_survive(self):
        self.results["safe_files"][self.path]["error"] = "standard timeout"
        self.record({"vulnerability_found": False, "error": "No payloads generated"})
        entry = self.results["safe_files"][self.path]
        self.assertEqual(entry["standard_result"]["error"], "standard timeout")
        self.assertEqual(entry["llm_details"]["error"], "No payloads generated")
        self.assertEqual(entry["status"], "inconclusive")
        self.assertFalse(entry["llm_tested"])

    def test_worker_exception_is_recorded(self):
        self.record(None, error=RuntimeError("API connection failed"))
        entry = self.results["safe_files"][self.path]
        self.assertEqual(entry["llm_details"]["error"], "API connection failed")
        self.assertFalse(entry["llm_tested"])

    def test_missing_result_is_an_error(self):
        self.record(None)
        entry = self.results["safe_files"][self.path]
        self.assertEqual(entry["llm_details"]["status"], "error")
        self.assertIn("LLM returned no result", entry["error"])

    def test_llm_finding_moves_category_and_preserves_both_counts(self):
        found = self.record({"vulnerability_found": True, "successful_payload": "<script>test</script>",
                             "custom_payloads_generated": 10, "custom_payloads_tested": 2})
        self.assertTrue(found)
        self.assertNotIn(self.path, self.results["safe_files"])
        entry = self.results["vulnerable_files"][self.path]
        self.assertEqual(entry["method"], "llm_enhanced")
        self.assertEqual(entry["test_count"], 5)
        self.assertEqual(entry["standard_result"], self.standard)
        self.assertEqual(entry["llm_details"]["standard_test_count"], 3)
        self.assertEqual(entry["llm_details"]["payloads_tested"], 2)

    def test_completed_negative_test_has_separate_stage_counts(self):
        self.record({"vulnerability_found": False, "custom_payloads_generated": 2,
                     "custom_payloads_tested": 2})
        entry = self.results["safe_files"][self.path]
        self.assertTrue(entry["llm_tested"])
        self.assertEqual(entry["llm_details"]["status"], "no_vulnerability_found")
        self.assertEqual(entry["test_count"], 5)
        self.assertEqual(entry["standard_result"], self.standard)


if __name__ == "__main__":
    unittest.main()
