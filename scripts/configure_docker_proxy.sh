#!/usr/bin/env bash
# Let the local Docker daemon use the desktop user's existing HTTP proxy.
set -euo pipefail
proxy_http=${HTTP_PROXY:-${http_proxy:-}}
proxy_https=${HTTPS_PROXY:-${https_proxy:-$proxy_http}}
if [ -z "$proxy_http" ] || [ -z "$proxy_https" ]; then
    echo '未检测到现有 HTTP_PROXY/HTTPS_PROXY；没有修改 Docker 配置。' >&2
    exit 1
fi
printf '为 Docker 服务配置当前用户已经使用的代理，需要本机 sudo 验证。\n'
sudo /usr/bin/python3 - "$proxy_http" "$proxy_https" <<'PY'
from datetime import datetime
import json, os, shutil, subprocess, sys
from pathlib import Path
from urllib.parse import urlsplit
for value in sys.argv[1:]:
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or parsed.hostname not in ('127.0.0.1', 'localhost') or parsed.username or parsed.password:
        raise SystemExit('本入口只复用无认证的本机代理，不处理或记录代理密码。')
path = Path('/etc/docker/daemon.json')
configuration = json.loads(path.read_text()) if path.exists() else {}
configuration['proxies'] = {'http-proxy': sys.argv[1], 'https-proxy': sys.argv[2],
                            'no-proxy': 'localhost,127.0.0.1,::1'}
path.parent.mkdir(parents=True, exist_ok=True)
temporary = path.with_name('.xss-daemon.json.tmp')
temporary.write_text(json.dumps(configuration, indent=2) + '\n')
temporary.chmod(0o644)
subprocess.run(['dockerd', '--validate', '--config-file', str(temporary)], check=True)
if path.exists():
    backup = path.with_name('daemon.json.before-xss-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    shutil.copy2(path, backup)
temporary.replace(path)
PY
sudo systemctl restart docker
sudo docker version --format 'Docker client={{.Client.Version}}, server={{.Server.Version}}'
printf '\nDocker 服务已使用现有本机代理。\n'
