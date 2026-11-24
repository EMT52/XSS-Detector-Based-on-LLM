#!/usr/bin/env bash
# Authenticate through ordinary Git's HTTPS prompt; never put tokens in files.
set -euo pipefail
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
state_file="$project_root/.docker-state/setup/publish.json"
repository=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["directory"])' "$state_file")
status() {
    /usr/bin/python3 - "$state_file" "$1" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
data = json.loads(path.read_text())
data['phase'] = sys.argv[2]
temporary = path.with_suffix('.tmp')
temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
temporary.replace(path)
PY
}
trap 'result=$?; if [ "$result" -ne 0 ]; then status push_failed; fi' EXIT
printf '使用普通 Git，通过 HTTPS 推送到：\n'
git -C "$repository" remote get-url origin
git -C "$repository" log -1 --format='%h %s'
printf '\n此提交只含已检查的源码与构建配置，不含待测应用、任务书、运行数据或 API Key。\n'
printf '若提示 Password，请在本机输入 GitHub 访问令牌，不能用账号登录密码。\n'
printf '令牌需要有目标仓库代码及工作流的写权限；不要把令牌发到聊天里。\n\n'
status waiting_for_https_authentication
GIT_TERMINAL_PROMPT=1 git -C "$repository" push -u origin main
status pushed
printf '\nHTTPS 推送完成；镜像是否发布以 GitHub Actions 的构建及检查结果为准。\n'
