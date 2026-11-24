"""End-to-end local check: AST → TChecker → Neo4j → PUT → Apache → Chrome."""
import json
import os
from pathlib import Path
import subprocess
import sys

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

ROOT = Path(os.environ.get('XSS_ROOT', '/workspace/XSS')).resolve()
sys.path.insert(0, str(ROOT / 'llm-xss/PUT_fuzzer'))
from models.helper_model import extract_main_param


def verify_served_put(web_root, origin='http://127.0.0.1'):
    put = Path(web_root) / 'php-app/1/index.php'
    parameter = extract_main_param(str(put))
    url = origin + '/php-app/1/index.php'
    marker = 'XSS_DOCKER_SMOKE'
    response = requests.get(url, params={parameter: marker}, timeout=10)
    response.raise_for_status()
    assert marker in response.text, response.text
    options = Options()
    options.binary_location = '/opt/chrome/chrome'
    for flag in ('--headless', '--no-sandbox', '--disable-dev-shm-usage'):
        options.add_argument(flag)
    driver = webdriver.Chrome(executable_path='/usr/local/bin/chromedriver/chromedriver', chrome_options=options)
    try:
        payload = '<script>window.__xssSmoke=711</script>'
        driver.get(requests.Request('GET', url, params={parameter: payload}).prepare().url)
        assert driver.execute_script('return window.__xssSmoke') == 711
    finally:
        driver.quit()


def main():
    # The wrapper supplies the container's dedicated Web root and runtime credentials.
    subprocess.run(['/usr/local/bin/xss', 'prepare', '--app', str(ROOT / 'examples/demo-app')], check=True)
    runs = ROOT / 'runs/preparation'
    latest = max((p for p in runs.iterdir() if p.is_dir()), key=lambda p: p.name)
    manifest = json.loads((latest / 'manifest.json').read_text())
    assert manifest['status'] == 'prepared' and manifest['put_count'] > 0
    assert (latest / 'deployment.json').is_file()
    verify_served_put(ROOT / '.docker-state/www')
    print('Smoke passed: AST, CPG, authenticated Neo4j, PUT, Apache PHP, browser execution. '
          'No LLM API call; sanitizer feedback instrumentation is not covered.')


if __name__ == '__main__':
    main()
