"""Initialize runtime credentials, run Apache, and drop task privileges."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request

ROOT = Path(os.environ.get('XSS_ROOT', '/workspace/XSS')).resolve()


def as_user(command, **kwargs):
    return subprocess.run(['runuser', '-u', 'xss', '--', 'env', 'HOME=/home/xss', *command],
                          check=True, **kwargs)


def initialize():
    if not (ROOT / 'scripts/prepare_step7.py').is_file():
        raise RuntimeError('Mount your XSS source directory at /workspace/XSS; this image contains only the runtime environment.')
    uid = int(os.environ.get('XSS_UID', '1000'))
    gid = int(os.environ.get('XSS_GID', '1000'))
    if uid <= 0 or gid <= 0:
        raise RuntimeError('XSS_UID and XSS_GID must be non-root IDs.')
    import pwd
    import grp
    if grp.getgrnam('xss').gr_gid != gid:
        subprocess.run(['groupmod', '-o', '-g', str(gid), 'xss'], check=True)
    if pwd.getpwnam('xss').pw_uid != uid:
        subprocess.run(['usermod', '-o', '-u', str(uid), '-g', str(gid), 'xss'], check=True)
    directories = ['.docker-state', '.docker-state/www', 'php-app', 'runs',
                   'llm-xss/PUT_extractor/storage', 'llm-xss/PUT_extractor/log',
                   'llm-xss/PUT_extractor/databases', 'llm-xss/PUT_fuzzer/output',
                   'llm-xss/PUT_fuzzer/feedback']
    for relative in directories:
        path = ROOT / relative
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, uid, gid)
    # Keep the web deployment and run backups on the same filesystem for atomic rename.
    web = ROOT / '.docker-state/www'
    alias = Path('/var/www/xss')
    if not alias.exists():
        alias.symlink_to(web, target_is_directory=True)
    (web / '__xss_health.php').write_text('<?php header("Content-Type: text/plain"); echo "xss-ok";')
    os.chmod(web / '__xss_health.php', 0o644)
    Path('/tmp/feedback').mkdir(exist_ok=True)
    os.chmod('/tmp/feedback', 0o1777)
    runtime = Path('/run/xss')
    runtime.mkdir(mode=0o700, exist_ok=True)
    os.chown(runtime, uid, gid)
    configuration = Path(os.environ['XSS_NEO4J_CONFIG'])
    auth = Path(os.environ['XSS_NEO4J_AUTH'])
    if not configuration.exists():
        password = os.environ.get('XSS_NEO4J_PASSWORD', '1')
        # /opt/neo4j is only an empty installation template; each run clones an empty DB.
        # Run the initializer as xss so subsequent Neo4j commands need no sudo.
        subprocess.run(['chown', '-R', f'{uid}:{gid}', '/opt/neo4j', '/home/xss'], check=True)
        as_user(['/opt/neo4j/bin/neo4j-admin', 'set-initial-password', password],
                stdout=subprocess.DEVNULL)
        configuration.write_text(json.dumps({'php-app': {
            'NEO4J_HOST': 'localhost', 'NEO4J_PORT': 7474,
            'NEO4J_USERNAME': 'neo4j', 'NEO4J_PASSWORD': password,
            'NEO4J_DATABASE': 'neo4j', 'NEO4J_PROTOCOL': 'http'}}))
        os.chmod(configuration, 0o600)
        os.chown(configuration, uid, gid)
    if not auth.is_file():
        raise RuntimeError('Neo4j initial authentication was not created.')
    as_user(['/usr/local/bin/xss', 'rebuild'])


def main():
    initialize()
    flavor = Path('/usr/local/share/xss/php-flavor').read_text().strip()
    print(f'PHP source flavor: {flavor}. Sanitizer instrumentation is not verified by container startup.', flush=True)
    apache = subprocess.Popen(['/usr/sbin/apachectl', '-D', 'FOREGROUND'])
    child = None

    def stop(signum, frame):
        if child and child.poll() is None:
            child.send_signal(signum)
        apache.send_signal(signum)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for _ in range(100):
            if apache.poll() is not None:
                raise RuntimeError('Apache failed to start.')
            try:
                with urllib.request.urlopen('http://127.0.0.1/__xss_health.php', timeout=1) as response:
                    if response.read() == b'xss-ok':
                        break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError('Apache PHP health check timed out.')
        args = sys.argv[1:] or ['serve']
        if args == ['serve']:
            return apache.wait()
        child = subprocess.Popen(['runuser', '-u', 'xss', '--', 'env', 'HOME=/home/xss',
                                  '/usr/local/bin/xss', *args])
        return child.wait()
    finally:
        if apache.poll() is None:
            subprocess.run(['/usr/sbin/apachectl', '-k', 'stop'], check=False)
            try:
                apache.wait(timeout=15)
            except subprocess.TimeoutExpired:
                apache.kill()
                apache.wait()


if __name__ == '__main__':
    sys.exit(main())
