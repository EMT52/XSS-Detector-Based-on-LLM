#!/usr/bin/env python3
"""Verify the JSON-input PUT using real PHP/Chrome, without sudo or an LLM.

The fixture is served on a temporary loopback port. Only the hardcoded localhost
origin in the existing tester is redirected to that port; responses, context
parsing, payload generation, and the browser oracle are unchanged.
Run from any directory: python scripts/verify_standard_gap.py
"""

import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FUZZER = ROOT / 'llm-xss/PUT_fuzzer'
sys.path.insert(0, str(FUZZER))

import requests
from models.context_model import context
from models.output_model import save_output
from models.verify_model import Sanitizer_Tester, webdriver


def main():
    fixture = FUZZER / 'fixtures/standard-gap/1/index.php'
    for path in fixture.parent.glob('*.php'):
        subprocess.run(['php', '-l', str(path)], check=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    real_get = requests.get
    real_chrome = webdriver.Chrome
    request_count = 0
    browser_count = 0

    def local_url(url):
        return url.replace('http://localhost/', origin + '/', 1)

    def local_get(url, *args, **kwargs):
        nonlocal request_count
        request_count += 1
        return real_get(local_url(url), *args, **kwargs)

    def local_chrome(*args, **kwargs):
        nonlocal browser_count
        browser_count += 1
        driver = real_chrome(*args, **kwargs)
        original_get = driver.get
        driver.get = lambda url: original_get(local_url(url))
        return driver

    with tempfile.TemporaryFile() as log:
        server = subprocess.Popen(
            ['php', '-S', f'127.0.0.1:{port}', '-t', str(FUZZER / 'fixtures')],
            stdout=log, stderr=log,
        )
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError('PHP server exited before becoming ready')
                try:
                    if real_get(origin + '/standard-gap/1/index.php', timeout=1).status_code == 200:
                        break
                except requests.RequestException:
                    pass
                time.sleep(0.05)
            else:
                raise RuntimeError('PHP server did not become ready')

            results = {'vulnerable_files': {}, 'safe_files': {}, 'cant_parse_files': []}
            tester = Sanitizer_Tester()
            start = time.monotonic()
            with patch('models.verify_model.requests.get', side_effect=local_get), \
                    patch('models.verify_model.webdriver.Chrome', side_effect=local_chrome):
                # Standard mode: real HTTP responses and the existing test_put.
                results = context(tester, enable_llm=False).test_put(str(fixture), results)
                assert not results['vulnerable_files'], results
                entry = results['safe_files'][str(fixture)]
                assert entry['test_count'] == 0 and 'Could not parse context' in entry['error'], entry
                assert not tester.get_error_files(), tester.error_details
                standard_requests = request_count
                standard_browsers = browser_count
                results['testing_duration'] = time.monotonic() - start

                # Same browser oracle and alert marker, with a structured payload.
                raw = '<svg onload=alert(711)></svg>'
                assert not tester.bugoracle(str(fixture), raw, 'null')
                payload = json.dumps({'html': raw}, separators=(',', ':'))
                response = tester.test_filter(str(fixture), payload, 'null')
                assert raw in response, response
                assert tester.bugoracle(str(fixture), payload, 'null'), 'No 711 alert'

            output = FUZZER / 'output/standard-gap.json'
            save_output(results, str(output))
            evidence = {
                'fixture': str(fixture),
                'llm_enabled': False,
                'standard_found': False,
                'standard_http_requests': standard_requests,
                'standard_browser_sessions': standard_browsers,
                'standard_test_count': entry['test_count'],
                'standard_reason': 'The plain probe is not a JSON object with an html field',
                'plain_html_payload_alert': False,
                'structured_payload': payload,
                'structured_payload_alert': '711',
                'validation': 'Existing bugoracle with real Chrome',
                'transport': 'Only localhost origin redirected to a temporary loopback PHP server',
            }
            evidence_path = FUZZER / 'output/standard-gap-evidence.json'
            evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')
            print(json.dumps(evidence, ensure_ascii=False, indent=2))
            print('PASS: standard mode misses the PUT; the structured payload triggers alert(711).')
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == '__main__':
    main()
