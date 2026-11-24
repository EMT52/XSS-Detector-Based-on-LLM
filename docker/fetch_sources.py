"""Fetch immutable, checksummed build inputs; never accept an unlocked input."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time
import urllib.request


def fetch(lock_path, directory, cache_directory=None):
    destination = Path(directory)
    destination.mkdir(parents=True, exist_ok=True)
    for name, source in json.loads(Path(lock_path).read_text()).items():
        checksum = source['sha256']
        target = destination / name
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == checksum:
            continue
        cached = Path(cache_directory) / name if cache_directory else None
        if cached and cached.is_file():
            if hashlib.sha256(cached.read_bytes()).hexdigest() != checksum:
                raise ValueError(f'{name}: cached source SHA256 mismatch')
            shutil.copyfile(cached, target)
            print(f'{name}: {source["version"]}, local cache SHA256 verified', flush=True)
            continue
        for attempt in range(3):
            digest = hashlib.sha256()
            try:
                with urllib.request.urlopen(source['url'], timeout=120) as response, target.open('wb') as stream:
                    while block := response.read(1024 * 1024):
                        stream.write(block)
                        digest.update(block)
                if digest.hexdigest() != checksum:
                    raise ValueError(f'{name}: SHA256 mismatch')
                break
            except Exception:
                target.unlink(missing_ok=True)
                if attempt == 2:
                    raise
                time.sleep(2)
        print(f'{name}: {source["version"]}, SHA256 verified', flush=True)


if __name__ == '__main__':
    fetch(*sys.argv[1:])
