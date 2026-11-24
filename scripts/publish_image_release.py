#!/usr/bin/env python3
"""Publish an already verified runtime image with the workflow's built-in token."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request


class GitHubError(RuntimeError):
    def __init__(self, status, message):
        super().__init__(f'GitHub HTTP {status}: {message}')
        self.status = status


def api(method, url, token, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json', 'User-Agent': 'xss-runtime-publisher',
    })
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            content = response.read()
            return json.loads(content) if content else None
    except urllib.error.HTTPError as error:
        try:
            message = json.loads(error.read()).get('message', 'Request failed')
        except (ValueError, AttributeError):
            message = 'Request failed'
        raise GitHubError(error.code, message) from None


def upload(url, path, token):
    target = urllib.parse.urlsplit(url)
    if target.scheme != 'https' or target.hostname != 'uploads.github.com':
        raise RuntimeError('Unexpected GitHub upload host')
    route = target.path + '?' + urllib.parse.urlencode({'name': path.name})
    connection = http.client.HTTPSConnection(target.hostname, timeout=300)
    try:
        connection.putrequest('POST', route)
        for key, value in {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/octet-stream',
            'Content-Length': str(path.stat().st_size),
            'User-Agent': 'xss-runtime-publisher',
        }.items():
            connection.putheader(key, value)
        connection.endheaders()
        digest = hashlib.sha256()
        with path.open('rb') as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                connection.send(chunk)
        response = connection.getresponse()
        result = json.loads(response.read())
        if response.status != 201:
            raise GitHubError(response.status, result.get('message', 'Asset upload failed'))
        if result.get('size') != path.stat().st_size or result.get('state') != 'uploaded':
            raise RuntimeError('GitHub asset upload was incomplete')
        if result.get('digest') and result['digest'] != 'sha256:' + digest.hexdigest():
            raise RuntimeError('GitHub asset checksum mismatch')
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('checksum', type=Path)
    args = parser.parse_args()
    token = os.environ['GITHUB_TOKEN']
    repository = os.environ['GITHUB_REPOSITORY']
    revision = os.environ['GITHUB_SHA']
    base = f'https://api.github.com/repos/{repository}/releases'
    tag = 'runtime-' + revision[:12]
    for path in (args.archive, args.checksum):
        if not path.is_file() or path.stat().st_size >= 2_000_000_000:
            raise RuntimeError('Missing or oversized release asset: ' + path.name)
    body = (
        '已通过容器内 AST、TChecker、Neo4j、PUT、Apache PHP 和真实 Chrome 检查。\n\n'
        '下载本页 Source code 和镜像包，在项目根目录执行：\n'
        '```bash\n'
        'sha256sum -c xss-env-linux-amd64.tar.gz.sha256\n'
        'docker load -i xss-env-linux-amd64.tar.gz\n'
        './进入环境.sh\n'
        '```\n'
        '公开 Release 的下载不需要访问令牌。进入 Bash 后可直接运行 Python、PHP、Java；'
        '源码和待测应用从宿主机挂载。Windows 使用 Docker Desktop + WSL2。\n\n'
        '镜像仅含运行环境，使用普通 PHP 7.0.33；不含 API Key、待测应用、任务书或实验数据。'
        'LLM 实际请求和 sanitizer 插桩反馈不在发布前检查范围内。\n\n'
        f'源码版本：`{revision}`。'
    )
    try:
        release = api('GET', base + '/tags/' + tag, token)
    except GitHubError as error:
        if error.status != 404:
            raise
        release = api('POST', base, token, {
            'tag_name': tag, 'target_commitish': revision,
            'name': 'XSS runtime ' + revision[:12], 'body': body, 'draft': True,
        })
    assets = api('GET', release['assets_url'], token)
    for path in (args.archive, args.checksum):
        for asset in assets:
            if asset['name'] == path.name:
                api('DELETE', asset['url'], token)
        upload(release['upload_url'].split('{', 1)[0], path, token)
    release = api('PATCH', release['url'], token, {
        'draft': False, 'body': body, 'make_latest': 'true',
    })
    print('Verified runtime download:', release['html_url'])


if __name__ == '__main__':
    main()
