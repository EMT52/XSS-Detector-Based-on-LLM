"""Regression checks for preparation boundaries and generated PHP semantics."""
import ast
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare', ROOT / 'scripts/prepare_step7.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PreparationRegression(unittest.TestCase):
    def test_raw_csv_count_preserves_non_utf8_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'nodes.csv'
            for content in (b'id\tcode\n1\tplain\n2\ttext\n',
                            b'id\tcode\n1\t"\x80\x81\xff"\n2\ttext\n'):
                with self.subTest(content=content):
                    path.write_bytes(content)
                    self.assertEqual(prepare.raw_csv_count(path), 2)
                    self.assertEqual(path.read_bytes(), content)

    def test_complete_static_report(self):
        self.assertEqual(prepare.read_paths('diagnostics\n[\n [14,21]\n]\n'), [[14, 21]])
        self.assertEqual(prepare.read_paths('diagnostics\n[\n]\n'), [])

    def test_incomplete_report_is_an_error(self):
        for text in ('diagnostics only', '[\n[14,21]', '[\n[true,21]\n]', '[\n[]\n]'):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                prepare.read_paths(text)

    def test_echo_keeps_output_context(self):
        tree = ast.parse((ROOT / 'llm-xss/PUT_extractor/PUT_extractor.py').read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == 'fix_php_syntax')
        namespace = {'re': re}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<extractor>', 'exec'), namespace)
        fix = namespace['fix_php_syntax']
        cases = [
            ('$name="MARKER"; echo("<h1>" . $name . "</h1>");', '<h1>MARKER</h1>'),
            ('''$name="MARKER"; echo("<div class='comment'>" . $name . "</div>");''',
             "<div class='comment'>MARKER</div>"),
            ('''$name="MARKER"; echo('<a title="' . $name . '">link</a>');''',
             '<a title="MARKER">link</a>'),
        ]
        for code, expected in cases:
            with self.subTest(code=code):
                actual = subprocess.run(['php', '-r', fix(code)], capture_output=True,
                                        text=True, check=True)
                self.assertEqual(actual.stdout, expected)


if __name__ == '__main__':
    unittest.main()
