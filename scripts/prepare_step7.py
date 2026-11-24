#!/usr/bin/env python3
"""Rebuild steps 1–6 in an isolated run and deploy PUTs for step 7."""
import argparse
import csv
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = ROOT / 'llm-xss/PUT_extractor'
TARGET = 'php-app'


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    tmp.replace(path)


def read_paths(log):
    # TChecker emits diagnostic text followed by one JSON array. Never accept
    # an absent/truncated result as an empty set of findings.
    for match in reversed(list(re.finditer(r'^\[\s*$', log, re.M))):
        try:
            paths = json.loads(log[match.start():])
        except json.JSONDecodeError:
            continue
        if (isinstance(paths, list) and all(
            isinstance(p, list) and p and all(type(n) is int and n >= 0 for n in p)
            for p in paths
        )):
            return paths
    raise RuntimeError('TChecker 未输出完整的污点路径 JSON，请查看 02-tchecker.log')


def command(argv, cwd, logfile, env, timeout, verbose=False):
    started = time.monotonic()
    print(f'  日志：{logfile}', flush=True)
    with logfile.open('w') as out:
        process = subprocess.Popen([str(a) for a in argv], cwd=cwd, env=env,
                                   stdout=out, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            # Read the log alongside the child so Python/C/JVM buffering cannot
            # block timeout handling, and long stages always show progress.
            with logfile.open(errors='replace') as live:
                next_progress = started + 15
                while True:
                    chunk = live.read()
                    if verbose and chunk:
                        print(chunk, end='', flush=True)
                    code = process.poll()
                    if code is not None:
                        chunk = live.read()
                        if verbose and chunk:
                            print(chunk, end='', flush=True)
                        break
                    now = time.monotonic()
                    if now - started >= timeout:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    if now >= next_progress:
                        print(f'  [进行中] {logfile.stem}，已用时 {now - started:.0f} 秒', flush=True)
                        next_progress = now + 15
                    time.sleep(0.1)
        except BaseException:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise
    text = logfile.read_text(errors='replace')
    if code:
        raise RuntimeError(f'命令退出码 {code}；日志：{logfile}\n{text[-2500:]}')
    print(f'  命令完成，耗时 {time.monotonic() - started:.1f} 秒', flush=True)
    return text


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def raw_csv_count(path):
    # Raw parser output may contain PHP byte strings that are not UTF-8.
    # Count physical lines without decoding or changing the source CSV;
    # text conversion is handled later by the existing CSV converter.
    with path.open('rb') as stream:
        return sum(1 for _ in stream) - 1


def csv_records(path):
    with path.open(newline='') as stream:
        rows = csv.reader(stream, delimiter='\t', strict=True)
        header = next(rows)
        count = 0
        ids = set()
        for row in rows:
            if len(row) != len(header):
                raise RuntimeError(f'{path}: 第 {rows.line_num} 行列数不匹配')
            count += 1
            if path.name == 'nodes.csv':
                if row[0] in ids:
                    raise RuntimeError(f'{path}: 重复节点 {row[0]}')
                ids.add(row[0])
        return count, ids


def source_hashes(source):
    return {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(source.rglob('*')) if p.is_file()}


def preflight(args):
    java_home = Path(args.java_home).resolve()
    php = shutil.which(os.environ.get('PHP7', 'php'))
    if not php or not (java_home / 'bin/java').is_file():
        raise RuntimeError('需要 PHP CLI 和 Java 11，可设置 PHP7 / JAVA_HOME')
    version = subprocess.check_output([str(java_home / 'bin/java'), '-version'],
                                      stderr=subprocess.STDOUT, text=True)
    if not re.search(r'version "11[.\"]', version):
        raise RuntimeError('TChecker/Neo4j 4.4 需要本项目已验证的 Java 11')
    config = json.loads(args.neo4j_config.read_text())[TARGET]
    home = Path(args.neo4j_home).resolve()
    required = [ROOT / 'phpjoern/src/Parser.php',
                ROOT / 'TChecker/bin/tools/php/ast2cpg/Main.class',
                home / 'bin/neo4j', home / 'bin/neo4j-admin', home / 'lib']
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise RuntimeError('缺少依赖：' + ', '.join(missing))
    # Reuse the working initial credential hash, never print credentials.
    auth = args.neo4j_auth
    if auth is None:
        auth = EXTRACTOR / 'databases/php-app/data/dbms/auth.ini'
        if not auth.is_file():
            auth = home / 'data/dbms/auth.ini'
    if not auth.is_file():
        raise RuntimeError('未找到已配置的 Neo4j auth.ini，请先完成一次数据库初始化')
    subprocess.run([sys.executable, '-c', 'import PUT_extractor'],
                   cwd=EXTRACTOR, check=True, stdout=subprocess.DEVNULL)
    if not args.app.is_dir() or not list(args.app.rglob('*.php')):
        raise RuntimeError(f'应用目录不存在或没有 .php 文件：{args.app}')
    return java_home, php, home, auth, config


def clone_database(home, auth, destination, http_port, bolt_port):
    for name in ('bin', 'conf', 'lib', 'plugins'):
        if (home / name).exists():
            shutil.copytree(home / name, destination / name)
    for name in ('data/dbms', 'logs', 'run', 'import'):
        (destination / name).mkdir(parents=True, exist_ok=True)
    shutil.copy2(auth, destination / 'data/dbms/auth.ini')
    # A separate, authenticated localhost instance. Do not delete or import
    # into /opt/neo4j, and do not borrow an unrelated server's ports.
    overrides = {
        'dbms.default_listen_address': '127.0.0.1',
        'dbms.default_advertised_address': '127.0.0.1',
        'dbms.connector.http.enabled': 'true',
        'dbms.connector.http.listen_address': f'127.0.0.1:{http_port}',
        'dbms.connector.http.advertised_address': f'127.0.0.1:{http_port}',
        'dbms.connector.bolt.enabled': 'true',
        'dbms.connector.bolt.listen_address': f'127.0.0.1:{bolt_port}',
        'dbms.connector.bolt.advertised_address': f'127.0.0.1:{bolt_port}',
        'dbms.connector.https.enabled': 'false',
        'dbms.security.auth_enabled': 'true',
        'dbms.memory.heap.initial_size': '256m',
        'dbms.memory.heap.max_size': '512m',
        'dbms.memory.pagecache.size': '256m',
    }
    conf = destination / 'conf/neo4j.conf'
    # Remove absolute storage paths from the template as well as overrides.
    lines = [line for line in conf.read_text().splitlines() if not (
        line.partition('=')[0].strip() in overrides or
        line.strip().startswith('dbms.directories.') or
        line.strip().startswith('dbms.active_database=') or
        line.strip().startswith('dbms.default_database='))]
    lines.extend(f'{key}={value}' for key, value in overrides.items())
    conf.write_text('\n'.join(lines) + '\n')


def deploy(run, web_root):
    manifest = json.loads((run / 'manifest.json').read_text())
    if manifest.get('status') != 'prepared':
        raise RuntimeError('该批次尚未通过步骤 1–6，不能部署')
    source = run / 'extractor/storage/PUT/php-app'
    destination = web_root / TARGET
    if not web_root.is_dir() or destination.is_symlink():
        raise RuntimeError('Web 根目录必须存在，且 php-app 不能是符号链接')
    backup = run / 'previous/web-php-app'
    if backup.exists():
        raise RuntimeError('本批次已保存过部署备份，请新建批次以免覆盖备份')
    temp = web_root / ('.php-app-' + run.name)
    if temp.exists():
        raise RuntimeError(f'部署临时目录已存在：{temp}')
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, temp)
    for p in [temp, *temp.rglob('*')]:
        p.chmod(0o755 if p.is_dir() else 0o644)
        # Match the guide's chown when deploying to the default Apache root.
        if web_root == Path('/var/www/html'):
            shutil.chown(p, user='www-data', group='www-data')
    moved = False
    try:
        if destination.exists():
            destination.rename(backup)
            moved = True
        temp.rename(destination)
    except BaseException:
        if moved and not destination.exists():
            backup.rename(destination)
        raise
    # Kept separate from manifest: sudo must not change manifest ownership.
    save_json(run / 'deployment.json', {'web_path': str(destination),
                                        'backup': str(backup) if moved else None})
    print(f'已部署 {manifest["put_count"]} 个 PUT：{destination}', flush=True)
    print(f'  旧部署备份：{backup if moved else "无旧部署"}', flush=True)
    print('  文件权限：目录 755、文件 644' +
          ('，所有者 www-data:www-data' if web_root == Path('/var/www/html') else ''), flush=True)


def request_deploy(run, web_root):
    if (web_root != Path('/var/www/html') or os.geteuid() == 0) and os.access(web_root, os.W_OK) and (
        not (web_root / TARGET).exists() or os.access(web_root / TARGET, os.W_OK)
    ):
        deploy(run, web_root)
    else:
        print('部署到 Apache 目录需要 sudo；请在终端输入系统密码。', flush=True)
        subprocess.run(['sudo', '--', sys.executable, str(Path(__file__).resolve()),
                        '--deploy-only', str(run), '--web-root', str(web_root)], check=True)


def publish(run, paths):
    destination = EXTRACTOR / 'storage/PUT/php-app'
    backup = run / 'previous/PUT/php-app'
    backup.parent.mkdir(parents=True, exist_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    source = run / 'extractor/storage/PUT/php-app'
    temp = destination.with_name('.php-app-' + run.name)
    shutil.copytree(source, temp)
    if destination.exists():
        destination.rename(backup)
    try:
        temp.rename(destination)
    except BaseException:
        if backup.exists():
            backup.rename(destination)
        raise
    flow_file = EXTRACTOR / 'storage/taint_flows/php-app.json'
    if flow_file.exists():
        shutil.copy2(flow_file, run / 'previous/taint-flows.json')
    save_json(flow_file, paths)


def prepare(args, run, manifest):
    print('[环境检查] 检查 PHP、Java、Python 依赖及 Neo4j 配置', flush=True)
    java_home, php, home, auth, config = preflight(args)
    print(f'[环境检查完成] Python={sys.executable}；PHP={php}；Java={java_home}', flush=True)
    env = dict(os.environ, JAVA_HOME=str(java_home), PHP7=php, PYTHONUNBUFFERED='1')
    # Ignore inherited paths which could redirect writes into another instance.
    for key in ('NEO4J_HOME', 'NEO4J_CONF'):
        env.pop(key, None)
    env['HEAP_SIZE'] = '512m'
    source = run / 'source/php-app'
    if run.is_relative_to(args.app):
        raise RuntimeError('应用目录不能包含本次运行目录')
    shutil.copytree(args.app, source)
    manifest['source_sha256'] = source_hashes(source)
    if source_hashes(args.app) != manifest['source_sha256']:
        raise RuntimeError('源码复制期间发生变化，请停止修改源码后重试')
    manifest['analysis_path'] = str(args.app)
    manifest['java_heap'] = args.java_heap
    manifest['java_version'] = subprocess.check_output(
        [str(java_home / 'bin/java'), '-version'], stderr=subprocess.STDOUT, text=True)
    manifest['python_version'] = sys.version
    manifest['php_version'] = subprocess.check_output([php, '-v'], text=True).splitlines()[0]
    cpg = run / 'cpg'
    cpg.mkdir()
    print('[1/6] PHP → AST', flush=True)
    # Analyze the original absolute source path, just like php2ast in the
    # manual workflow; absolute includes and file-based CPG lookups depend on it.
    text = command([php, ROOT / 'phpjoern/src/Parser.php', args.app], cpg,
                   run / '01-phpjoern.log', env, args.timeout, args.verbose)
    if re.search(r'\[ERROR\]|Fatal error|Parse error', text, re.I):
        raise RuntimeError('PHP 解析器报告错误；查看 01-phpjoern.log')
    raw_counts = {}
    for name in ('nodes.csv', 'rels.csv'):
        raw_counts[name] = raw_csv_count(cpg / name)
    print(f'[1/6 完成] AST 节点 {raw_counts["nodes.csv"]}，AST 关系 {raw_counts["rels.csv"]}', flush=True)
    print(f'  产物：{cpg / "nodes.csv"}、{cpg / "rels.csv"}', flush=True)
    print('[2/6] TChecker 静态分析', flush=True)
    jars = [ROOT / 'TChecker/bin',
            ROOT / 'TChecker/ApacheCommons/commons-cli-1.4/commons-cli-1.4.jar',
            ROOT / 'TChecker/ApacheCommons/commons-csv-1.8-bin/commons-csv-1.8/commons-csv-1.8.jar',
            ROOT / 'TChecker/ApacheCommons/commons-lang3-3.10/commons-lang3-3.10.jar',
            ROOT / 'TChecker/ApacheCommons/json-20190722.jar']
    text = command([java_home / 'bin/java', '-Xmx' + args.java_heap, '-cp',
                    os.pathsep.join(map(str, jars)), 'tools.php.ast2cpg.Main', args.app],
                   cpg, run / '02-tchecker.log', env, args.timeout, args.verbose)
    paths = read_paths(text)
    manifest['taint_flow_count'] = len(paths)
    save_json(run / 'taint-flows.json', paths)
    print(f'[2/6 完成] TChecker 报告 {len(paths)} 条候选路径，Java 堆上限 {args.java_heap}', flush=True)
    for i, path in enumerate(paths, 1):
        print(f'  路径 {i}：{path}', flush=True)
    print(f'  CPG：{cpg / "cpg_edges.csv"}', flush=True)
    if not paths:
        manifest['status'] = 'no_paths'
        print('TChecker 未报告候选路径，本批次无 PUT；停止，不进入步骤 7。旧部署未改动。')
        return 3
    print('[3/6] CSV 校验与导入全新 Neo4j 数据库', flush=True)
    fixed = run / 'fixed'
    text = command([sys.executable, ROOT / 'neo4j-import-data/fix_csv_for_neo4j_admin.py',
                    '--nodes', cpg / 'nodes.csv', '--rels', cpg / 'rels.csv',
                    cpg / 'cpg_edges.csv', '--output-dir', fixed],
                   run, run / '03-csv.log', env, args.timeout, args.verbose)
    if re.search(r'错误:\s*[1-9]|⚠', text):
        raise RuntimeError('CSV 转换丢弃了数据，请查看 03-csv.log')
    counts = {}
    for name in ('nodes.csv', 'rels.csv', 'cpg_edges.csv'):
        count, ids = csv_records(fixed / name)
        # The converter is line based: reject dropped/split records.
        original_count = raw_csv_count(cpg / name)
        if count != original_count:
            raise RuntimeError(f'{name}: CSV 转换前后记录数量不一致')
        counts[name] = count
        if name == 'nodes.csv' and any(str(n) not in ids for p in paths for n in p):
            raise RuntimeError('污点路径引用了不存在的 AST 节点')
    manifest['csv_counts'] = counts
    print(f'  CSV 校验通过：节点 {counts["nodes.csv"]}，AST 关系 {counts["rels.csv"]}，CPG 关系 {counts["cpg_edges.csv"]}', flush=True)
    http_port, bolt_port = free_port(), free_port()
    while http_port == bolt_port:
        bolt_port = free_port()
    db = run / 'neo4j'
    clone_database(home, auth, db, http_port, bolt_port)
    # Existing extractor Cypher queries compare id to string literals. Keep
    # STRING IDs, as in the previously verified manual import, or POST source
    # adapters and call-site discovery can silently disappear.
    command([db / 'bin/neo4j-admin', 'import', '--database=neo4j', '--id-type=STRING',
             '--delimiter=TAB', '--quote="', '--multiline-fields=true',
             '--nodes=' + str(fixed / 'nodes.csv'),
             '--relationships=' + str(fixed / 'rels.csv'),
             '--relationships=' + str(fixed / 'cpg_edges.csv')],
            run, run / '03-import.log', env, args.timeout, args.verbose)
    print(f'[3/6 完成] 已导入全新 neo4j 数据库：{db / "data/databases/neo4j"}', flush=True)
    print('[4/6] 启动独立 Neo4j，核对节点与关系数量', flush=True)
    config.update(NEO4J_HOST='127.0.0.1', NEO4J_PORT=http_port,
                  NEO4J_PROTOCOL='http', NEO4J_DATABASE='neo4j')
    ext = run / 'extractor'
    ext.mkdir()
    shutil.copy2(EXTRACTOR / 'PUT_extractor.py', ext / 'PUT_extractor.py')
    shutil.copytree(EXTRACTOR / 'config', ext / 'config')
    shutil.copytree(EXTRACTOR / 'core', ext / 'core',
                    ignore=shutil.ignore_patterns('__pycache__'))
    (ext / 'databases').mkdir()
    (ext / 'databases/php-app').symlink_to(db, target_is_directory=True)
    save_json(ext / 'config/neo4j.json', {TARGET: config})
    os.chmod(ext / 'config/neo4j.json', 0o600)
    try:
        command([db / 'bin/neo4j', 'start'], run, run / '04-start.log', env, 60, args.verbose)
        print(f'  等待认证查询就绪：HTTP 127.0.0.1:{http_port}，Bolt 127.0.0.1:{bolt_port}', flush=True)
        import py2neo
        deadline = time.monotonic() + 90
        graph = None
        while time.monotonic() < deadline:
            try:
                graph = py2neo.Graph(f'http://127.0.0.1:{http_port}',
                                     auth=(config['NEO4J_USERNAME'], config['NEO4J_PASSWORD']),
                                     name='neo4j')
                actual_nodes = graph.evaluate('MATCH (n) RETURN count(n)')
                actual_rels = graph.evaluate('MATCH ()-[r]->() RETURN count(r)')
                break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError('Neo4j 90 秒内未就绪，请检查认证配置及 neo4j/logs')
        if (actual_nodes != counts['nodes.csv'] or
                actual_rels != counts['rels.csv'] + counts['cpg_edges.csv']):
            raise RuntimeError('数据库节点/关系数量与本批次 CSV 不一致')
        manifest['graph_counts'] = {'nodes': actual_nodes, 'relationships': actual_rels}
        print(f'[4/6 完成] 认证查询通过：{actual_nodes} 个节点，{actual_rels} 条关系，与 CSV 一致', flush=True)
        print('[5/6] 自动写入本次污点路径', flush=True)
        save_json(ext / 'storage/taint_flows/php-app.json', paths)
        print(f'[5/6 完成] 已写入 {len(paths)} 条路径：{ext / "storage/taint_flows/php-app.json"}', flush=True)
        print(f'[6/6] 提取 {len(paths)} 个 PUT，逐文件检查 PHP 语法', flush=True)
        # Own the database lifecycle here; call run directly so extraction
        # exceptions propagate, unlike the legacy CLI which catches them.
        command([sys.executable, '-c', 'from PUT_extractor import run; run("php-app")'],
                ext, run / '06-extractor.log', env, args.timeout, args.verbose)
        puts = ext / 'storage/PUT/php-app'
        expected = {str(i) for i in range(1, len(paths) + 1)}
        actual = {p.name for p in puts.iterdir() if p.is_dir()} if puts.exists() else set()
        if actual != expected or any(not (puts / i / 'index.php').is_file() or
                                     not (puts / i / 'function_definition.php').is_file()
                                     for i in expected):
            raise RuntimeError('PUT 数量或文件不完整；查看 06-extractor.log')
        for i in expected:
            print(f'  PUT {i}：index.php、function_definition.php 文件完整', flush=True)
        lint = []
        for p in sorted(puts.rglob('*.php')):
            result = subprocess.run([php, '-l', str(p)], capture_output=True, text=True,
                                    timeout=30)
            lint.append(result.stdout + result.stderr)
            if result.returncode:
                (run / '06-php-lint.log').write_text(''.join(lint))
                raise RuntimeError(f'生成的 PHP 语法错误：{p}；不发布本批次')
        (run / '06-php-lint.log').write_text(''.join(lint))
        manifest['put_count'] = len(actual)
        manifest['php_files_linted'] = len(lint)
        print(f'[6/6 完成] {len(actual)} 个 PUT，{len(lint)} 个 PHP 文件语法检查全部通过', flush=True)
        print(f'  PUT 目录：{puts}', flush=True)
    finally:
        command([db / 'bin/neo4j', 'stop'], run, run / '04-stop.log', env, 90, args.verbose)
        print('[数据库关闭完成] 已停止本批次独立实例', flush=True)
    if source_hashes(args.app) != manifest['source_sha256']:
        raise RuntimeError('分析期间源码发生变化，本批次不发布，请停止修改后重试')
    if not args.no_publish:
        publish(run, paths)
        print(f'[发布完成] PUT：{EXTRACTOR / "storage/PUT/php-app"}', flush=True)
        print(f'  污点路径：{EXTRACTOR / "storage/taint_flows/php-app.json"}', flush=True)
        print(f'  旧产物备份：{run / "previous"}', flush=True)
    else:
        print('[发布已跳过] --no-publish 保留共享产物，结果只存本批次目录', flush=True)
    manifest['status'] = 'prepared'
    return 0


def main():
    parser = argparse.ArgumentParser(description='一键重建步骤 1–6，部署后停在步骤 7 入口')
    parser.add_argument('--app', type=Path, default=ROOT / 'php-app', help='待测 PHP 应用目录')
    parser.add_argument('--java-home', default=os.environ.get('JAVA_HOME', '/usr/lib/jvm/java-11-openjdk-amd64'))
    parser.add_argument('--java-heap', default='8G', help='TChecker 堆上限，默认 8G，与操作指南一致')
    parser.add_argument('--neo4j-home', default='/opt/neo4j', help='Neo4j 4.4 安装模板')
    parser.add_argument('--neo4j-config', type=Path,
                        default=Path(os.environ.get('XSS_NEO4J_CONFIG',
                                                   EXTRACTOR / 'config/neo4j.json')),
                        help='Neo4j 连接配置；容器使用独立运行时配置')
    parser.add_argument('--neo4j-auth', type=Path,
                        default=os.environ.get('XSS_NEO4J_AUTH'),
                        help='指定初始认证文件，不复用其他环境的认证')
    parser.add_argument('--web-root', type=Path, default=Path('/var/www/html'))
    parser.add_argument('--skip-deploy', action='store_true', help='仅完成步骤 1–6')
    parser.add_argument('--no-publish', action='store_true', help='验证用：不更新共享 PUT/污点路径文件')
    parser.add_argument('--check-only', action='store_true', help='仅检查依赖和配置')
    parser.add_argument('--deploy-only', type=Path, help='部署已通过验证的批次，不重复分析')
    parser.add_argument('--timeout', type=int, default=1800, help='单个分析命令超时秒数')
    parser.add_argument('--verbose', action='store_true', help='在控制台实时显示各工具的完整日志')
    args = parser.parse_args()
    args.app = args.app.resolve()
    args.web_root = args.web_root.resolve()
    if args.deploy_only:
        run = args.deploy_only.resolve()
        if os.geteuid() == 0:
            deploy(run, args.web_root)
        else:
            request_deploy(run, args.web_root)
        return 0
    if os.geteuid() == 0:
        raise RuntimeError('请以普通用户运行；只有最终 Web 部署使用 sudo')
    if args.check_only:
        preflight(args)
        print('依赖检查通过。尚未执行静态分析、数据库导入或 PUT 提取。')
        return 0
    runs = ROOT / 'runs/preparation'
    runs.mkdir(parents=True, exist_ok=True)
    with (runs / '.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('已有准备流程在运行，请等待完成')
        run = runs / datetime.now().strftime('%Y%m%d-%H%M%S-%f')
        run.mkdir(mode=0o700)
        manifest = {'status': 'running', 'app': str(args.app), 'run': str(run),
                    'started_at': datetime.now().astimezone().isoformat(),
                    'published': not args.no_publish}
        print(f'本批次记录：{run}', flush=True)
        try:
            code = prepare(args, run, manifest)
        except BaseException as exc:
            manifest.update(status='failed', error=str(exc))
            raise
        finally:
            manifest['finished_at'] = datetime.now().astimezone().isoformat()
            save_json(run / 'manifest.json', manifest)
        if code:
            return code
        if not args.skip_deploy:
            request_deploy(run, args.web_root)
        print(f'步骤 1–6 已通过：{manifest["put_count"]} 个 PUT。', flush=True)
        if args.skip_deploy:
            print(f'已跳过部署；后续执行：./prepare_step7.sh --deploy-only {run}')
        else:
            print('已到达步骤 7 入口；PUT_fuzzer 尚未运行。')
        print(f'日志及实验记录：{run / "manifest.json"}')
        return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as exc:
        print(f'准备流程停止：{exc}', file=sys.stderr)
        sys.exit(1)
