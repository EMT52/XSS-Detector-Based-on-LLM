#!/usr/bin/env bash
# Connect ordinary Git to the requested repository without GitHub CLI.
set -euo pipefail
umask 077
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
setup_dir="$project_root/.docker-state/setup"
mkdir -p "$setup_dir" "$HOME/.ssh"
chmod 0700 "$HOME/.ssh"
key="$HOME/.ssh/id_ed25519_xss_github"
hosts="$HOME/.ssh/xss_github_known_hosts"
remote='ssh://git@ssh.github.com:443/EMT52/XSS-Detector-Based-on-LLM.git'

status() {
    /usr/bin/python3 - "$setup_dir/github-ssh.json" "$1" "$key" "$hosts" "$remote" <<'PY'
import json, shlex, sys
from pathlib import Path
path = Path(sys.argv[1])
ssh = ['ssh', '-i', sys.argv[3], '-o', 'IdentitiesOnly=yes', '-o',
       'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + sys.argv[4],
       '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=20']
temporary = path.with_suffix('.tmp')
temporary.write_text(json.dumps({'phase': sys.argv[2], 'key_path': sys.argv[3],
                                'known_hosts_path': sys.argv[4], 'remote_url': sys.argv[5],
                                'ssh_command': shlex.join(ssh)}) + '\n')
temporary.replace(path)
PY
}
trap 'result=$?; if [ "$result" -ne 0 ]; then status failed; fi' EXIT

status creating_key
if [ ! -f "$key" ]; then
    printf '为此项目创建独立 SSH 密钥。请在本机终端设置密钥口令。\n'
    ssh-keygen -t ed25519 -a 64 -f "$key" -C 'EMT52 XSS project'
elif [ ! -f "$key.pub" ]; then
    ssh-keygen -y -f "$key" > "$key.pub"
fi
if [ -n "${SSH_AUTH_SOCK:-}" ]; then
    ssh-add "$key"
fi

# GitHub's published Ed25519 host key, verified in the official documentation.
# https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
printf '%s\n' '[ssh.github.com]:443 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' > "$hosts"
status waiting_for_public_key_registration
printf '\n请复制下面以 ssh-ed25519 开头的完整一行公钥：\n\n'
cat "$key.pub"
printf '\n在 GitHub 页面填写 Title（例如 XSS），Key type 选择 Authentication Key，\n'
printf '把这行公钥粘贴到 Key 后保存。请登录对 EMT52/XSS-Detector-Based-on-LLM 有写权限的账号。\n'
xdg-open 'https://github.com/settings/ssh/new' >/dev/null 2>&1 || true
read -r -p '在网页添加公钥完成后，按回车验证连接：'

ssh_command=$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ssh_command"])' "$setup_dir/github-ssh.json")
status verifying
git -c core.sshCommand="$ssh_command" ls-remote "$remote"
status complete
printf '\n普通 Git 的 SSH 连接已验证；未安装或使用 GitHub CLI。\n'
