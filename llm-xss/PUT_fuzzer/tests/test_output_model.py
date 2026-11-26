import copy
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from requests import ConnectionError, Response, Timeout

from models import context_model, output_model
from models.llm_enhanced_model import LLMEnhancedTester, llm_enhanced_test, llm_static_analysis_test


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
        second = run_results(safe={"new-app/2": {
            "note": "No vulnerability found", "test_count": 2,
            "standard_result": {"test_count": 2},
        }}, duration=2)
        self.save(first)
        first_bytes = self.output.read_bytes()
        self.save(second)
        self.assertEqual(json.loads(self.output.read_text()), second)
        history = list((self.output.parent / "history").glob("*.json"))
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].read_bytes(), first_bytes)

    def test_retested_path_can_change_classification_in_either_direction(self):
        finding = run_results(vulnerable={"app/1": {
            "note": "Vulnerability found by standard test", "payload": "payload",
            "test_count": 1, "standard_result": {"test_count": 1},
        }})
        no_finding = run_results(safe={"app/1": {
            "note": "No vulnerability found", "test_count": 2,
            "standard_result": {"test_count": 2},
        }})
        for expected in (finding, no_finding, finding):
            self.save(expected)
            self.assertEqual(json.loads(self.output.read_text()), expected)

    def test_duplicate_categories_are_disjoint_without_mutating_caller(self):
        results = run_results(vulnerable={"app/1": {}}, safe={"app/1": {}, "app/2": {}})
        results["cant_parse_files"] = ["app/1", "app/2", "app/3", "app/3"]
        original = copy.deepcopy(results)
        self.save(results)
        saved = json.loads(self.output.read_text())
        self.assertEqual(set(saved["safe_files"]), {"app/2"})
        self.assertEqual(saved["safe_files"]["app/2"]["note"], "Testing incomplete")
        self.assertEqual(saved["cant_parse_files"], ["app/3"])
        self.assertEqual(results, original)

    def test_corrupt_old_json_is_archived_without_blocking_new_run(self):
        self.output.parent.mkdir()
        old = b'{"interrupted":'
        self.output.write_bytes(old)
        expected = run_results(safe={"新项目/1": {
            "note": "Testing incomplete", "test_count": 0,
            "standard_result": {"test_count": 0, "error": "未完成"},
        }})
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
        invalid = run_results(vulnerable={"app/1": {"payload": object()}})
        with self.assertRaises(TypeError):
            self.save(invalid)
        self.assertEqual(self.output.read_bytes(), before)

    def test_legacy_standard_finding_has_ordered_fields_and_stage_count(self):
        results = run_results(vulnerable={"app/1": {
            "method": "standard", "payload": "payload", "test_count": 3,
        }})
        self.save(results)
        entry = json.loads(self.output.read_text())["vulnerable_files"]["app/1"]
        self.assertEqual(list(entry), ["note", "payload", "test_count", "standard_result"])
        self.assertEqual(entry, {
            "note": "Vulnerability found by standard test", "payload": "payload",
            "test_count": 3, "standard_result": {"test_count": 3},
        })

    def test_legacy_llm_result_is_migrated_and_repeated_saves_are_stable(self):
        results = run_results(safe={"app/1": {
            "note": "LLM testing completed; no vulnerability found",
            "status": "not_detected", "test_count": 2, "llm_tested": True,
            "standard_result": {"test_count": 0, "note": "Could not parse context, will be tested by LLM if enabled"},
            "llm_details": {"provider": "deepseek", "status": "no_vulnerability_found",
                            "payloads_generated": 2, "payloads_tested": 2, "standard_test_count": 0},
        }})
        self.save(results)
        saved = json.loads(self.output.read_text())
        entry = saved["safe_files"]["app/1"]
        self.assertEqual(entry, {
            "note": "Testing incomplete", "test_count": 2,
            "standard_result": {"test_count": 0, "error": "Could not parse context"},
            "LLM_result": {"provider": "deepseek", "payloads_generated": 2,
                           "payloads_tested": 2, "failed_response": None},
        })
        first_bytes = self.output.read_bytes()
        self.save(saved)
        self.assertEqual(self.output.read_bytes(), first_bytes)


class LLMResultTests(unittest.TestCase):
    def setUp(self):
        self.path = "app/2/index.php"
        self.standard = {"test_count": 3, "note": "standard stage finished"}
        self.expected_standard = {"test_count": 3}
        self.results = run_results(safe={self.path: copy.deepcopy(self.standard)})

    def record(self, result, **kwargs):
        return output_model.record_llm_result(
            self.results, self.path, result, "deepseek", **kwargs
        )

    def test_zero_payloads_are_not_marked_tested(self):
        self.record({"vulnerability_found": False, "custom_payloads_generated": 0,
                     "custom_payloads_tested": 0})
        entry = self.results["safe_files"][self.path]
        self.assertEqual(entry["note"], "Testing incomplete")
        self.assertEqual(entry["LLM_result"]["payloads_tested"], 0)
        self.assertEqual(entry["LLM_result"]["error"], "No LLM payloads tested")
        self.assertEqual(entry["standard_result"], self.expected_standard)
        self.assertNotIn("payload", entry)

    def test_llm_error_and_standard_error_both_survive(self):
        self.results["safe_files"][self.path]["error"] = "standard timeout"
        self.record({"vulnerability_found": False, "error": "No payloads generated"})
        entry = self.results["safe_files"][self.path]
        self.assertEqual(entry["standard_result"]["error"], "standard timeout")
        self.assertEqual(entry["LLM_result"]["error"], "No payloads generated")
        self.assertEqual(entry["note"], "Testing incomplete")
        self.assertNotIn("error", entry)

    def test_worker_exception_is_recorded(self):
        self.record(None, error=RuntimeError("API connection failed"))
        entry = self.results["safe_files"][self.path]
        self.assertEqual(entry["LLM_result"]["error"], "RuntimeError: API connection failed")
        self.assertIsNone(entry["LLM_result"]["failed_response"])
        self.assertEqual(entry["note"], "Testing incomplete")

    def test_empty_model_content_preserves_original_http_body(self):
        body = '{"choices":[{"message":{"content":""},"finish_reason":"length"}]}'
        response = Response()
        response.status_code = 200
        response._content = body.encode("utf-8")
        with (
            patch("models.llm_payload.requests.post", return_value=response),
            patch.object(LLMEnhancedTester, "analyze_php_code", return_value={}),
            patch.object(LLMEnhancedTester, "_build_llm_prompt", return_value=""),
            patch.object(LLMEnhancedTester, "test_custom_payloads") as verify,
            self.assertLogs("models.output_model", level="WARNING") as logs,
        ):
            result = llm_enhanced_test(None, self.path, {}, provider="deepseek", api_key="mock")
            self.record(result)

        verify.assert_not_called()
        details = self.results["safe_files"][self.path]["LLM_result"]
        self.assertIn("LLM response content is empty", details["error"])
        self.assertEqual(details["failed_response"], body)
        self.assertEqual(len(logs.output), 1)
        self.assertIn(repr(body), logs.output[0])

    def test_missing_result_is_an_error(self):
        self.record(None)
        entry = self.results["safe_files"][self.path]
        self.assertEqual(entry["note"], "Testing incomplete")
        self.assertIn("LLM returned no result", entry["LLM_result"]["error"])

    def test_llm_finding_moves_category_and_preserves_both_counts(self):
        found = self.record({"vulnerability_found": True, "successful_payload": "<script>test</script>",
                             "custom_payloads_generated": 10, "custom_payloads_tested": 2})
        self.assertTrue(found)
        self.assertNotIn(self.path, self.results["safe_files"])
        entry = self.results["vulnerable_files"][self.path]
        self.assertEqual(entry["note"], "Vulnerability found by LLM")
        self.assertEqual(list(entry)[:3], ["note", "payload", "test_count"])
        self.assertEqual(entry["test_count"], 5)
        self.assertEqual(entry["standard_result"], self.expected_standard)
        self.assertEqual(entry["LLM_result"]["payloads_tested"], 2)
        forbidden = {"status", "method", "llm_tested", "llm_details", "standard_test_count"}
        for section in (entry, entry["standard_result"], entry["LLM_result"]):
            self.assertTrue(forbidden.isdisjoint(section))
        self.assertNotIn("note", entry["standard_result"])
        self.assertNotIn("note", entry["LLM_result"])

    def test_completed_negative_test_has_separate_stage_counts(self):
        self.record({"vulnerability_found": False, "custom_payloads_generated": 2,
                     "custom_payloads_tested": 2})
        entry = self.results["safe_files"][self.path]
        self.assertEqual(entry["note"], "No vulnerability found")
        self.assertEqual(list(entry)[:2], ["note", "test_count"])
        self.assertEqual(entry["LLM_result"]["payloads_tested"], 2)
        self.assertEqual(entry["test_count"], 5)
        self.assertEqual(entry["standard_result"], self.expected_standard)

    def test_negative_llm_test_keeps_standard_timeout_incomplete(self):
        self.results["safe_files"][self.path]["error"] = "standard timeout"
        self.record({"vulnerability_found": False, "custom_payloads_generated": 2,
                     "custom_payloads_tested": 2})
        entry = self.results["safe_files"][self.path]
        self.assertEqual(entry["note"], "Testing incomplete")
        self.assertEqual(entry["standard_result"]["error"], "standard timeout")


class LLMResponseTests(unittest.TestCase):
    entry_points = (
        ("normal", llm_enhanced_test, {"context_info": {}}),
        ("static", llm_static_analysis_test, {}),
    )

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "index.php"
        self.path.write_text("<?php echo 'test';", encoding="utf-8")

    def run_entry(self, entry_point, kwargs, response=None, error=None, found=False):
        analysis = {"sanitizers": [], "filters": [], "input_params": [], "output_points": []}
        verification = (found, "probe" if found else None, 2)
        results = run_results(safe={str(self.path): {"test_count": 3}})
        with (
            patch("models.llm_payload.requests.post", return_value=response, side_effect=error),
            patch.object(LLMEnhancedTester, "analyze_php_code", return_value=analysis),
            patch.object(LLMEnhancedTester, "_static_code_analysis", return_value=analysis),
            patch.object(LLMEnhancedTester, "_build_llm_prompt", return_value=""),
            patch.object(LLMEnhancedTester, "_build_static_analysis_prompt", return_value=""),
            patch.object(LLMEnhancedTester, "test_custom_payloads", return_value=verification),
            patch.object(LLMEnhancedTester, "_test_payloads_without_context", return_value=verification),
            self.assertLogs(level="INFO"),
            redirect_stderr(StringIO()),
            redirect_stdout(StringIO()),
        ):
            result = entry_point(None, str(self.path), provider="deepseek", api_key="mock", **kwargs)
            output_model.record_llm_result(results, str(self.path), result, "deepseek")
            output = Path(self.directory.name) / "results.json"
            output_model.save_output(results, output)
        group = "vulnerable_files" if found else "safe_files"
        return json.loads(output.read_text())[group][str(self.path)]

    def response(self, body, status=200):
        response = Response()
        response.status_code = status
        response.encoding = "utf-8"
        response._content = body.encode("utf-8")
        return response

    def test_response_failures_keep_specific_causes_and_full_bodies(self):
        cases = (
            ("HTTP failure", '{"error":{"message":"quota exhausted"}}', 429, "HTTPError"),
            ("invalid JSON", '{"choices":', 200, "LLM response JSON parsing failed"),
            ("empty HTTP body", "", 200, "LLM response JSON parsing failed"),
            ("missing message", '{}', 200, "KeyError"),
            ("empty content", '{"choices":[{"message":{"content":""}}]}', 200, "LLM response content is empty"),
            ("invalid content", '{"choices":[{"message":{"content":"Unable to comply"}}]}',
             200, "LLM response content could not be parsed into payloads"),
            ("empty payload list", '{"choices":[{"message":{"content":"[]"}}]}',
             200, "LLM response contained no usable payloads"),
        )
        for mode, entry_point, kwargs in self.entry_points:
            for name, body, status, cause in cases:
                with self.subTest(mode=mode, failure=name):
                    entry = self.run_entry(entry_point, kwargs, self.response(body, status))
                    self.assertEqual(entry["note"], "Testing incomplete")
                    self.assertIn(cause, entry["LLM_result"]["error"])
                    self.assertEqual(entry["LLM_result"]["failed_response"], body)

    def test_requests_without_responses_keep_causes_and_explicit_null(self):
        for mode, entry_point, kwargs in self.entry_points:
            for error in (Timeout("read timed out"), ConnectionError("connection refused")):
                with self.subTest(mode=mode, failure=type(error).__name__):
                    entry = self.run_entry(entry_point, kwargs, error=error)
                    details = entry["LLM_result"]
                    self.assertEqual(entry["note"], "Testing incomplete")
                    self.assertIn(type(error).__name__, details["error"])
                    self.assertIn(str(error), details["error"])
                    self.assertIn("failed_response", details)
                    self.assertIsNone(details["failed_response"])

    def test_completed_negative_tests_keep_full_original_response(self):
        body = json.dumps({"choices": [{"message": {"content": '["probe"]'}}],
                           "metadata": "原始响应🧪" * 6000}, ensure_ascii=False, indent=2)
        for mode, entry_point, kwargs in self.entry_points:
            with self.subTest(mode=mode):
                entry = self.run_entry(entry_point, kwargs, self.response(body))
                self.assertEqual(entry["note"], "No vulnerability found")
                self.assertEqual(entry["LLM_result"]["failed_response"], body)
                self.assertNotIn("error", entry["LLM_result"])
                self.assertEqual(entry["test_count"], 5)

    def test_successful_tests_keep_the_agreed_success_format(self):
        body = '{"choices":[{"message":{"content":"[\\"probe\\"]"}}]}'
        for mode, entry_point, kwargs in self.entry_points:
            with self.subTest(mode=mode):
                entry = self.run_entry(entry_point, kwargs, self.response(body), found=True)
                self.assertEqual(list(entry)[:3], ["note", "payload", "test_count"])
                self.assertEqual(entry["note"], "Vulnerability found by LLM")
                self.assertNotIn("failed_response", entry["LLM_result"])


class StandardResultTests(unittest.TestCase):
    def test_standard_entry_points_save_findings_negatives_and_failures(self):
        cases = (
            ("finding", {1: {"context": "html"}}, ("payload", 2), None,
             "vulnerable_files", "Vulnerability found by standard test"),
            ("negative", {1: {"context": "html"}}, ({}, 2), None,
             "safe_files", "No vulnerability found"),
            ("parse failure", None, ({}, 0), None,
             "safe_files", "Testing incomplete"),
            ("browser error", {1: {"context": "html"}}, ({}, 0), RuntimeError("browser unavailable"),
             "safe_files", "Testing incomplete"),
        )
        for name, parsed, grammar_result, error, group, note in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                results = run_results()
                path = "app/1/index.php"
                with (
                    patch.object(context_model, "fuzz_cases", ["probe"]),
                    patch.object(context_model, "context_parser", return_value=parsed),
                    patch.object(context_model.Tags, "html_attackgrammar",
                                 return_value=grammar_result, side_effect=error),
                ):
                    context_model.context(Mock()).test_put(path, results)
                output = Path(directory) / "results.json"
                with redirect_stdout(StringIO()):
                    output_model.save_output(results, output)
                entry = json.loads(output.read_text())[group][path]
                self.assertEqual(entry["note"], note)
                self.assertNotIn("LLM_result", entry)
                if note == "Testing incomplete":
                    self.assertTrue(entry["standard_result"]["error"])
                    self.assertNotIn("error", entry)
                if group == "vulnerable_files":
                    self.assertEqual(list(entry)[:3], ["note", "payload", "test_count"])

    def test_standard_timeout_is_saved_inside_standard_result(self):
        results = run_results()
        path = "app/1/index.php"
        with patch.object(context_model, "timeout_handler", side_effect=context_model.TimeoutException):
            context_model.context(Mock()).test_put(path, results, timeout=3)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.json"
            with redirect_stdout(StringIO()):
                output_model.save_output(results, output)
            entry = json.loads(output.read_text())["safe_files"][path]
        self.assertEqual(entry["note"], "Testing incomplete")
        self.assertEqual(entry["standard_result"], {"test_count": 0, "error": "timeout_3s"})
        self.assertNotIn("error", entry)


if __name__ == "__main__":
    unittest.main()
