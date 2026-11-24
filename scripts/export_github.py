#!/usr/bin/env python3
"""Export stable source, flatten nested repositories, and reject embedded keys.

This never edits the nested TChecker/phpjoern repositories or reads their history.
Run without --output to inspect only; export requires a new destination directory.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {'.git', '.gradle', '__pycache__', 'bin', 'databases', 'storage',
                 'log', 'output', '.docker-state', '.pipeline-verification', 'dist',
                 'runs', 'php-app', 'apps', 'venv', '.pytest_cache', '.mypy_cache'}
TOP_LEVEL = {'TChecker', 'phpjoern', 'llm-xss', 'neo4j-import-data', 'scripts',
             'docker', '.github', 'examples', '操作'}
TOP_FILES = {'Dockerfile', 'compose.yaml', '.dockerignore', '.gitignore',
             '.gitattributes', '.env.example', 'prepare_step7.sh', 'init.sh'}
KEY_PATTERNS = [re.compile(pattern.encode()) for pattern in (
    r'sk-[A-Za-z0-9_-]{16,}', r'gh[pousr]_[A-Za-z0-9_]{20,}',
    r'github_pat_[A-Za-z0-9_]{20,}', r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')]


def selected(path):
    relative = path.relative_to(ROOT)
    if relative.as_posix() == '任务书.md':
        return False
    if len(relative.parts) == 1:
        return path.name in TOP_FILES or path.suffix == '.md'
    if relative.parts[0] not in TOP_LEVEL:
        return False
    if any(part in EXCLUDED_DIRS or part.startswith(('.venv', '.compile-'))
           for part in relative.parts[:-1]):
        return False
    if '.compile-' in str(relative) or path.suffix in ('.csv', '.pyc', '.report'):
        return False
    if '.backup' in path.name or path.name == 'php-instr.tar.gz':
        return False
    if path.name.startswith('.env') and path.name != '.env.example':
        return False
    if path.name == 'neo4j.json' and path.parent.name == 'config':
        return False
    if 'feedback' in relative.parts and path.suffix == '.log':
        return False
    if relative.parts[:2] == ('docker', 'vendor') and path.name != 'README.md':
        return False
    if relative.parts[:2] == ('docker', '.wheel-cache') and path.name != 'README.md':
        return False
    return True


def scan(files):
    findings = []
    for path in files:
        # Binary archives are handled by the allowlist, not decoded or dumped.
        if path.suffix.lower() in ('.jar', '.png', '.jpg', '.gif', '.pdf', '.zip', '.gz'):
            continue
        data = path.read_bytes()
        for line_number, line in enumerate(data.splitlines(), 1):
            if any(pattern.search(line) for pattern in KEY_PATTERNS):
                findings.append(f'{path.relative_to(ROOT)}:{line_number}')
    if findings:
        raise RuntimeError('Potential credentials; values withheld: ' + ', '.join(findings))


def export(output=None):
    files = []
    for entry in ROOT.iterdir():
        if entry.is_file() and selected(entry):
            files.append(entry)
        elif entry.is_dir() and entry.name in TOP_LEVEL:
            for directory, children, names in os.walk(entry, followlinks=False):
                children[:] = [name for name in children if name not in EXCLUDED_DIRS
                               and not name.startswith(('.venv', '.compile-'))]
                files.extend(p for name in names if selected(p := Path(directory) / name))
    files.sort()
    if any(p.is_symlink() for p in files):
        raise RuntimeError('Inspect source symlinks before publishing.')
    scan(files)
    if output is None:
        print(f'Source scan passed: {len(files)} selected files; no key pattern found.')
        return
    output = Path(output).resolve()
    if output == ROOT or output.exists():
        raise RuntimeError('Export destination must be a new directory.')
    # Freeze the list before creating output, even when exporting under dist/.
    output.mkdir(parents=True)
    manifest = {}
    for path in files:
        relative = path.relative_to(ROOT)
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        manifest[str(relative)] = hashlib.sha256(destination.read_bytes()).hexdigest()
    (output / 'source-export.json').write_text(json.dumps({
        'exported_at': datetime.now().astimezone().isoformat(), 'sha256': manifest},
        ensure_ascii=False, indent=2) + '\n')
    print(f'Exported {len(files)} stable source files: {output}')
    print('Nested Git metadata, target applications, runtime databases, credentials, and results were excluded.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--scan-only', action='store_true')
    args = parser.parse_args()
    if args.scan_only and args.output:
        parser.error('--scan-only and --output cannot be combined')
    try:
        export(args.output)
    except (OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
