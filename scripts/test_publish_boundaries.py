"""Ensure the GitHub export never includes local applications or credentials."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('export_github.py'))
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class PublishBoundaries(unittest.TestCase):
    def test_local_data_and_nested_history_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(publisher, 'ROOT', root):
                for name in ('php-app/index.php', 'runs/batch/manifest.json', '.env', '任务书.md',
                             'TChecker/.git/config', 'TChecker/bin/Main.class',
                             'llm-xss/.venv/lib/module.py',
                             'llm-xss/.venv-py312-backup/bin/python',
                             'llm-xss/PUT_extractor/config/neo4j.json',
                             'llm-xss/PUT_extractor/databases/php-app/data/dbms/auth.ini',
                             'docker/vendor/php-instrumented.tar.gz'):
                    with self.subTest(name=name):
                        self.assertFalse(publisher.selected(root / name))
                for name in ('TChecker/projects/extensions/StaticAnalysis.java',
                             'phpjoern/src/Parser.php', 'docker/requirements.lock',
                             '.env.example', '操作指南.md'):
                    self.assertTrue(publisher.selected(root / name))

    def test_key_detection_reports_location_without_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guide = root / '操作指南.md'
            fake_key = 'sk-' + 'A' * 32
            guide.write_text('key=' + fake_key)
            with patch.object(publisher, 'ROOT', root):
                with self.assertRaises(RuntimeError) as raised:
                    publisher.scan([guide])
            self.assertIn('操作指南.md:1', str(raised.exception))
            self.assertNotIn(fake_key, str(raised.exception))

    def test_environment_reference_can_be_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guide = root / '操作指南.md'
            guide.write_text('--llm_api_key "$DEEPSEEK_API_KEY"')
            with patch.object(publisher, 'ROOT', root):
                publisher.scan([guide])


if __name__ == '__main__':
    unittest.main()
