from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from models.helper_model import extract_main_param
from models.verify_model import Sanitizer_Tester


class InputParameterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'php-app' / '1' / 'index.php'
        self.path.parent.mkdir(parents=True)
        self.path.with_name('function_definition.php').write_text('')

    def write_put(self, code):
        self.path.write_text('<?php\n' + code, encoding='utf-8')
        return str(self.path)

    def test_get_adapter_uses_input_instead_of_overwritten_target(self):
        for name in ('name', 'id'):
            with self.subTest(name=name):
                path = self.write_put(f'$_GET["{name}"] = $_GET[\'input\'];\n$value = $_GET["{name}"];')
                self.assertEqual(extract_main_param(path), 'input')

    def test_post_adapter_uses_get_input(self):
        path = self.write_put('$_POST["comment"] = $_GET[\'input\'];')
        self.assertEqual(extract_main_param(path), 'input')

    def test_adapter_accepts_spaces_and_quote_styles(self):
        path = self.write_put('$_GET [ "name" ] = $_GET [ "input" ];')
        self.assertEqual(extract_main_param(path), 'input')

    def test_scalar_source_adapter_takes_precedence_over_other_get_params(self):
        path = self.write_put('$mode = $_GET["mode"];\n$source = $_GET["input"];')
        self.assertEqual(extract_main_param(path), 'input')

    def test_unadapted_put_keeps_original_parameter_even_if_input_also_exists(self):
        path = self.write_put('echo $_GET["q"];\necho $_GET["input"];')
        self.assertEqual(extract_main_param(path), 'q')

    def test_legacy_rule_still_skips_temp_parameters(self):
        path = self.write_put('echo $_GET["temp_value"];\necho $_GET["search"];')
        self.assertEqual(extract_main_param(path), 'search')

    def test_probe_request_injects_input(self):
        path = self.write_put('$_GET["name"] = $_GET["input"];\necho $_GET["name"];')
        response = Mock(status_code=200, content=b'PROBE_711')
        with patch('models.verify_model.requests.get', return_value=response) as get:
            self.assertEqual(Sanitizer_Tester().test_filter(path, 'PROBE_711', 'null'), 'PROBE_711')
        self.assertEqual(get.call_args.kwargs['params'], {'input': 'PROBE_711'})

    def test_browser_verification_uses_the_same_input_parameter(self):
        path = self.write_put('$_GET["id"] = $_GET["input"];\necho $_GET["id"];')
        driver = Mock()
        driver.switch_to.alert.text = '711'
        with patch('models.verify_model.webdriver.Chrome', return_value=driver), \
                patch('models.verify_model.os.path.isfile', return_value=True):
            self.assertTrue(Sanitizer_Tester().bugoracle(path, 'PROBE_711', 'null'))
        query = parse_qs(urlsplit(driver.get.call_args.args[0]).query)
        self.assertEqual(query, {'input': ['PROBE_711']})
        driver.quit.assert_called_once()


if __name__ == '__main__':
    unittest.main()
