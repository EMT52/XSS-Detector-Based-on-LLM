"""Regression checks for preparation boundaries and generated PHP semantics."""
import ast
import csv
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

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

    def test_tchecker_reports_request_values_written_directly_to_output(self):
        checker = ROOT / 'TChecker'
        java = Path(os.environ.get('JAVA_HOME', '/usr/lib/jvm/java-11-openjdk-amd64')) / 'bin/java'
        apache = checker / 'ApacheCommons'
        jars = [checker / 'bin', apache / 'commons-cli-1.4/commons-cli-1.4.jar',
                apache / 'commons-csv-1.8-bin/commons-csv-1.8/commons-csv-1.8.jar',
                apache / 'commons-lang3-3.10/commons-lang3-3.10.jar', apache / 'json-20190722.jar']
        cases = (
            ("if (isset($_GET['value'])) { echo $_GET['value']; }", True),
            ("echo 'prefix ' . ($_GET['value'] ?? '');", True),
            ("print $_POST['value'];", True),
            ('''echo "prefix {$_GET['value']}";''', True),
            ("echo htmlspecialchars($_GET['value'], ENT_QUOTES, 'UTF-8');", False),
            ("echo isset($_GET['value']) ? 'present' : 'missing';", False),
            ("$labels = ['example' => 'constant']; echo $labels[$_GET['value']];", False),
            ("$value = $_GET['value']; echo $value;", True),
        )
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            app = run / 'app'
            app.mkdir()
            (app / 'index.php').write_text('<?php\n' + '\n'.join(code for code, _ in cases) + '\n')
            subprocess.run([os.environ.get('PHP7', 'php'), ROOT / 'phpjoern/src/Parser.php', app],
                           cwd=run, capture_output=True, check=True)
            result = subprocess.run([java, '-cp', os.pathsep.join(map(str, jars)),
                                     'tools.php.ast2cpg.Main', app], cwd=run,
                                    capture_output=True, text=True, errors='replace', check=True)
            paths = prepare.read_paths(result.stdout)
            with (run / 'nodes.csv').open(newline='') as stream:
                rows = csv.reader(stream, delimiter='\t')
                next(rows)
                nodes = {int(row[0]): (row[2], row[4]) for row in rows}
            output_paths = {int(nodes[path[-1]][1]): path for path in paths
                            if nodes[path[-1]][0] in {'AST_ECHO', 'AST_PRINT'}}
            self.assertEqual(set(output_paths), {line for line, (_, reported) in enumerate(cases, 2)
                                                if reported})
            self.assertEqual(len(output_paths[2]), 1)
            self.assertGreater(len(output_paths[len(cases) + 1]), 1)

    def test_publish_preserves_all_put_files_in_standard_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'batch'
            put_path = Path('storage/PUT/php-app')
            files = {'1/index.php': '<?php echo (= 1);\n',
                     '1/function_definition.php': '<?php\n',
                     '2/index.php': '<?php echo 2;\n',
                     '2/function_definition.php': '<?php\n'}
            for name, contents in files.items():
                path = run / 'extractor' / put_path / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)

            extractor = root / 'shared'
            with patch.object(prepare, 'EXTRACTOR', extractor):
                prepare.publish(run, [[1, 2], [3, 4]])

            self.assertEqual({p.name for p in (extractor / 'storage').iterdir()},
                             {'PUT', 'taint_flows'})
            published = extractor / put_path
            self.assertEqual({str(p.relative_to(published)): p.read_text()
                              for p in published.rglob('*') if p.is_file()}, files)

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
