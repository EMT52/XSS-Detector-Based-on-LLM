"""Regression checks for preparation boundaries and generated PHP semantics."""
import ast
import importlib.util
import os
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

    def test_php_parser_skips_invalid_files_without_dangling_relationships(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            app = run / 'app'
            invalid_dir = app / 'invalid-only'
            invalid_dir.mkdir(parents=True)
            (app / 'valid.php').write_text('<?php echo 1;\n')
            (app / 'invalid.php').write_text('<?php echo (= 1);\n')
            (invalid_dir / 'invalid.php').write_text('<?php echo (= 2);\n')

            result = subprocess.run([os.environ.get('PHP7', 'php'),
                                     ROOT / 'phpjoern/src/Parser.php', app], cwd=run,
                                    capture_output=True, text=True, check=True)

            self.assertEqual(result.stderr.count('[ERROR] In '), 2)
            nodes = (run / 'nodes.csv').read_text()
            self.assertIn('valid.php', nodes)
            self.assertNotIn('invalid.php', nodes)
            self.assertNotIn('invalid-only', nodes)
            node_ids = {row.split('\t', 1)[0] for row in nodes.splitlines()[1:]}
            relationships = (run / 'rels.csv').read_text().splitlines()[1:]
            self.assertTrue(relationships)
            for relationship in relationships:
                start, end, _ = relationship.split('\t')
                self.assertIn(start, node_ids)
                self.assertIn(end, node_ids)

    def test_lint_archives_only_failed_puts(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            puts = run / 'PUT'
            lint_log = run / '06-php-lint.log'
            archive = run / 'storage/failed_puts/batch'
            valid = '<?php echo 1;\n'
            invalid = '<?php echo (= 1);\n'
            for put_id, index, definitions in (('1', invalid, valid), ('2', valid, valid),
                                                ('3', valid, invalid)):
                put = puts / put_id
                put.mkdir(parents=True)
                (put / 'index.php').write_text(index)
                (put / 'function_definition.php').write_text(definitions)

            with self.assertRaisesRegex(RuntimeError, '生成的 PHP 语法错误：.*1/index.php；不发布本批次'):
                prepare.lint_puts(os.environ.get('PHP7', 'php'), puts, lint_log, archive)

            self.assertEqual({path.name for path in archive.iterdir()}, {'1', '3', lint_log.name})
            self.assertEqual((archive / '1/index.php.txt').read_text(), invalid)
            self.assertEqual((archive / '1/function_definition.php.txt').read_text(), valid)
            self.assertEqual((archive / '3/function_definition.php.txt').read_text(), invalid)
            self.assertEqual(list(archive.rglob('*.php')), [])
            log = lint_log.read_text()
            self.assertEqual(log, (archive / lint_log.name).read_text())
            self.assertIn(f'No syntax errors detected in {puts / "3/index.php"}', log)

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
