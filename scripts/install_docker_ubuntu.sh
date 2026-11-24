#!/usr/bin/env bash
# Install Ubuntu's Docker packages. GitHub authentication is independent.
# Run as the desktop user so sudo authentication happens locally.
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
setup_dir="$project_root/.docker-state/setup"
mkdir -p "$setup_dir"
state_file="$setup_dir/status.json"

write_status() {
    /usr/bin/python3 - "$state_file" "$1" <<'PY'
import json, sys
from datetime import datetime
from pathlib import Path
path = Path(sys.argv[1])
temporary = path.with_suffix('.tmp')
temporary.write_text(json.dumps({'phase': sys.argv[2],
                                'updated_at': datetime.now().astimezone().isoformat()}) + '\n')
temporary.replace(path)
PY
}

on_exit() {
    local result=$1
    if [ "$result" -ne 0 ]; then
        write_status failed
        printf '\n安装未完成（退出码 %s）。请保留终端中的错误信息。\n' "$result"
    fi
}
trap 'on_exit "$?"' EXIT

if [ "$(id -u)" -eq 0 ]; then
    echo '请以普通桌面用户运行此脚本；脚本会按需调用 sudo。' >&2
    exit 1
fi
. /etc/os-release
if [ "$ID" != ubuntu ] || [ "${VERSION_CODENAME:-}" != noble ]; then
    echo '本安装入口针对已检查的 Ubuntu 24.04（noble）。' >&2
    exit 1
fi

write_status waiting_for_sudo
printf '将在本机安装 Docker Engine、Compose 和 Buildx。\n'
printf '请在此终端输入系统 sudo 密码，密码不会写入项目或发送到聊天。\n'
sudo -v

write_status installing_packages
sudo apt-get update --allow-releaseinfo-change-label
sudo apt-get install -y ca-certificates curl docker.io docker-buildx docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker "$(id -un)"

sudo docker version
docker compose version
docker buildx version
write_status docker_installed
printf '\nDocker 已安装并启动。已将当前用户加入 docker 组。\n'
printf '现有终端可能需要重新登录，或使用 sg docker 刷新组权限。\n'

write_status complete
printf '\nDocker 安装已完成。GitHub 通过现有 Git 单独连接，不需要 GitHub CLI。\n'
