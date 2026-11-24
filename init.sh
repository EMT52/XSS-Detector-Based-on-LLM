#!/usr/bin/env bash
# Start the prepared environment, then open an ordinary interactive shell.
set -euo pipefail
project_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_root"
if ! command -v docker >/dev/null 2>&1; then
    printf '请先安装 Docker 和 Compose；Windows 请从启用了 Docker Desktop 集成的 WSL 终端运行。\n' >&2
    exit 1
fi
if [ "${1:-}" = '--pull' ]; then
    docker compose pull lab
    shift
fi
docker compose up -d --no-build --wait --wait-timeout 180 lab
printf '\n即将进入容器 Bash：代码目录 /workspace/XSS。\n'
printf '可直接使用 cd、python、php、java 等命令；exit 只退出终端，环境继续运行。\n\n'
exec docker compose exec --user xss --workdir /workspace/XSS lab bash "$@"
