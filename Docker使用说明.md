# Docker 实验环境

## 文件范围与实现状态

镜像只提供运行环境，不内置 `XSS/` 实验源码；代码和数据全部从宿主机挂载。
GitHub 保存当前 `XSS/` 文件夹中的工具和代码。`php-app/` 是可更换的待测应用，
不进入 GitHub 发布包；历史运行、数据库、日志、结果、`.env` 和本机
Neo4j 认证配置也不进入发布包。`任务书.md` 仅本地保留，不上传也不进入镜像。
仓库内含一个小型示例应用，用于挂载后检查环境。

Dockerfile、Compose、GitHub Actions 和运行入口已提供。
本机已安装 Ubuntu 软件源提供的 Docker 29.1.3、Compose 2.40.3 和 Buildx 0.30.1，
客户端与服务端连接正常，`hello-world` 镜像拉取及容器运行通过；实验容器正在首次构建。
只有容器内
构建及 smoke 全部通过后，才能认定相应镜像通过了下述检查。
上传源代码本身不代表镜像已经构建、测试或发布成功。

2026-11-24 本机验证：从现有源码完整重编译 TChecker 成功；7 项准备/发布边界
检查和 20 项 fuzzer 回归检查通过；示例应用的步骤 1～6 实跑得到 1 条候选路径、
1 个 PUT 和 2 个通过语法检查的 PHP 文件，Neo4j 查询核对为 27 个节点、30 条关系。
生成的 PUT 随后通过本机临时 PHP 服务及真实 Chrome 的脚本执行标记检查。
普通 PHP 7.0.33 源码及 ast 0.1.4 也在临时目录成功编译并验证 AST 版本 30；
Neo4j 4.4.37 的临时认证初始化已确认接受密码 `1`。全部下载输入均已取得
SHA256，Chrome ZIP 另通过完整 CRC 检查。
这组证据验证了示例和检查逻辑，不能替代容器内的完整检查。

## 固定的版本

| 组件 | 版本或锁定方式 |
| --- | --- |
| Linux 用户空间 | Ubuntu 22.04，基础镜像按 SHA256 digest 固定 |
| Python | 3.10.22，源码 SHA256 校验 |
| Python 包 | `docker/requirements.lock`，来自当前可用环境的完整版本快照 |
| PHP CLI / Apache 模块 | 普通 PHP 7.0.33，同一份源码构建 |
| PHP ast | 0.1.4，commit `701e8539e0a861b8fe3c0144a7554c376f42efe3` |
| Java | OpenJDK 11；Ubuntu 安全补丁版本由构建时软件源决定 |
| Neo4j | Community 4.4.37，源码包 SHA256 校验 |
| Chrome / ChromeDriver | 同为 158.0.8127.36，分别校验下载包 SHA256 |
| TChecker | 不打入镜像；挂载后用宿主机当前 Java 源码及随附 JAR 编译 |

下载地址和校验值在 `docker/sources.lock.json`。系统库、Apache、JDK 的补丁版本
未全部锁到 apt 快照；因此源码重建不保证逐字节一致。需要保持同一批运行环境时，
拉取发布的镜像 digest，而不是重新构建或长期依赖可变的 `latest` 标签。
镜像内 `/usr/local/share/xss/` 保存实际系统包和 Python 包清单。

目前目标平台为 `linux/amd64`，适用于常见 Intel/AMD Windows/Linux 机器。
更换 ARM 机器需要另行验证模拟运行或提供 ARM 浏览器构建。

## 本机构建和使用

当前 Ubuntu 24.04 主机的安装入口是 `bash scripts/install_docker_ubuntu.sh`，
只安装 Docker、Compose、Buildx，不安装 GitHub CLI。
仓库按用户习惯使用现有 Git 和 HTTPS；不要求创建 SSH 密钥。
如果以后选择 SSH，也提供了可选入口 `bash scripts/connect_github_ssh.sh`。
本机凭据、私钥和口令不写入项目发布包。
加入 docker 组后，旧登录会话可先执行 `newgrp docker` 刷新组权限。

当前主机的 Docker 服务需要复用已存在的本机代理。
`bash scripts/configure_docker_proxy.sh` 仅为 Docker 服务配置该代理，不改变系统代理。
如果代理只监听宿主机回环地址，构建阶段需要使用宿主机网络，例如：

```bash
docker build --network=host \
  --build-arg UBUNTU_MIRROR=http://mirrors.tuna.tsinghua.edu.cn/ubuntu \
  --build-arg HTTP_PROXY="$HTTP_PROXY" --build-arg HTTPS_PROXY="$HTTPS_PROXY" \
  --build-arg http_proxy="$HTTP_PROXY" --build-arg https_proxy="$HTTPS_PROXY" \
  --build-arg NO_PROXY=localhost,127.0.0.1,mirrors.tuna.tsinghua.edu.cn \
  --build-arg no_proxy=localhost,127.0.0.1,mirrors.tuna.tsinghua.edu.cn \
  -t xss-env:local .
```

`UBUNTU_MIRROR` 只替换 Ubuntu 软件源地址，仍验证 Ubuntu 的签名；不指定时使用原始源。
这属于当前 Linux 主机的联网设置；普通可直连主机仍可使用下面的 Compose 构建命令。

在项目根目录执行，先将一个待测应用的源码放进 `php-app/`：

```bash
cp .env.example .env
docker compose build
docker compose up -d
docker compose ps
docker compose exec --user xss lab xss versions
docker compose exec --user xss lab xss check
docker compose exec --user xss lab xss prepare
docker compose exec --user xss lab xss fuzz --output output/php-app.json
```

`prepare` 沿用原步骤 1～6，完成后部署 PUT，停在步骤 7 入口。
`fuzz` 才执行浏览器测试。结果保存在本机
`llm-xss/PUT_fuzzer/output/php-app.json`，每批准备记录在 `runs/preparation/`。
容器 Web 根目录位于 `.docker-state/www/`，与本批次备份保持在同一文件系统，
避免跨文件系统的目录重命名失败。Apache 与浏览器在同一容器中，保留原代码的
`http://localhost/` 行为。Web 端口仅映射到宿主机 `127.0.0.1:8080`。

Linux 下若文件所属 UID/GID 不是 1000，在 `.env` 设置 `XSS_UID`、`XSS_GID`
为 `id -u`、`id -g` 的输出。不要用 root 的 UID/GID。容器以普通用户运行分析流程。

## 修改代码、换应用

整个项目目录挂载到容器的 `/workspace/XSS`，包括代码、待测应用和输出文件。
容器启动辅助脚本也从本机 `docker/` 目录只读挂载，宿主机仍可编辑。
修改 Python/PHP 后再次执行命令即可；
修改 TChecker Java 源码后，`xss prepare` 会自动检测内容哈希并重新编译。
单独编译可用：

```bash
docker compose exec --user xss lab xss rebuild
```

更换 `php-app/` 内的应用，执行 `xss prepare`，随后执行 `xss fuzz`。
也可以把多个应用放在本机 `apps/`，逐个指定：

```bash
docker compose exec --user xss lab xss prepare --app /workspace/XSS/apps/my-app
```

当前共享输出及 Web 部署名称仍统一为 `php-app`，新一次准备会替换上一共享结果，
同时保留批次记录；不要并发准备或测试不同应用。应用存放路径不要含 `test`，
避免触发原 TChecker 的路径过滤。新 PHP 特性、原生扩展或额外服务仍需单独验证。
更改依赖或 PHP 源码时，需要重建镜像。

## Windows 使用

安装 WSL2，并启用 Docker Desktop 的 WSL2 后端和 Linux containers。
建议从 WSL 终端克隆项目到 `~/XSS`，把代码保留在 Linux 文件系统中；
VS Code 可以通过 WSL 扩展打开这个目录。然后执行上面的 Compose 命令。
无需在 Windows 本机再安装 Java、Neo4j、Python、PHP 或 ChromeDriver。

## API Key 与 Neo4j 凭据

不要把真实密钥写入文档、Dockerfile、构建参数或 GitHub 仓库。
在本机 `.env` 设置 `DEEPSEEK_API_KEY`，该文件已忽略；更新环境变量后重建容器：

```bash
docker compose up -d --force-recreate
docker compose exec --user xss lab xss fuzz --output output/php-app.json \
  --enable_llm --llm_provider deepseek --llm_model "你实际使用的模型名称"
```

Fuzzer 已支持从环境变量读取 Key，因此无需把 Key 写进命令行。
Neo4j 默认连接配置与下面的示例一致，密码为用户指定的 `1`。
连接配置保存在权限受限的容器运行时文件中。
准备脚本使用这些独立凭据，不读取或修改本机已有认证配置。
`--check-only` 只检查依赖，不代表完整实验已通过。

```json
{
  "php-app": {
    "NEO4J_HOST": "localhost",
    "NEO4J_PORT": 7474,
    "NEO4J_USERNAME": "neo4j",
    "NEO4J_PASSWORD": "1",
    "NEO4J_DATABASE": "neo4j",
    "NEO4J_PROTOCOL": "http"
  }
}
```

容器启动不会常驻一个 7474 服务；准备脚本仍为每个批次分配本地空闲端口，
并将对应配置写入该批次的 `extractor/config/neo4j.json`，结束后关闭数据库。
更改 `.env` 的 `XSS_NEO4J_PASSWORD` 后需要重建容器，命令同上。

## 验证与插桩范围

```bash
docker compose exec --user xss lab xss smoke
```

这会用 `examples/demo-app` 重跑 AST、TChecker、独立且需要认证的 Neo4j、PUT 提取、
PHP 语法、Apache 响应和真实 Chrome 执行标记。它会替换共享 PUT 和 Web 部署，
因此在正式应用实验前运行，或在单独容器中执行：

```bash
docker run --rm --shm-size=1g \
  -e XSS_UID="$(id -u)" -e XSS_GID="$(id -g)" \
  --mount "type=bind,source=$PWD,target=/workspace/XSS" \
  ghcr.io/emt52/xss-detector-based-on-llm:latest smoke
```

检查不调用 LLM API，不验证 sanitizer feedback。上面的独立容器仍使用相同挂载
目录，会替换该目录的共享 PUT；需要保留正式部署时，先复制一份源码目录用于检查。
原 `llm-xss/php-instr.tar.gz` 实际是 Software Heritage 的文件缺失提示。
默认普通 PHP 镜像可用于上述流程，但不能宣称完整复现论文插桩反馈机制。
真实插桩源码的接入方法见 `docker/vendor/README.md`；提供源码后仍需单独验证反馈内容。

## GitHub 与镜像同步

目标仓库：`https://github.com/EMT52/XSS-Detector-Based-on-LLM`。
代码和构建配置进入 Git 仓库，镜像进入
`ghcr.io/emt52/xss-detector-based-on-llm`，不把大型镜像 tar 提交到 Git。

当前本地根目录不是 Git 仓库，TChecker/phpjoern 各有独立 Git 元数据。
为保留本地修改并避免意外只上传子模块指针，使用导出器生成普通目录形式的源码：

```bash
python scripts/export_github.py --scan-only
python scripts/export_github.py --output dist/github-source
```

导出前会检查常见密钥模式，发现时只报告文件位置，不显示值。
导出器不复制嵌套 Git 历史、应用、数据库、日志或结果。应将导出内容合并到
目标仓库的新分支并检查 diff，再推送；不要直接覆盖远端历史。

对当前空仓库，导出目录内可使用普通 Git 的 HTTPS 流程：

```bash
git init -b main
git add .
git commit -m "Add portable experiment environment"
git remote add origin https://github.com/EMT52/XSS-Detector-Based-on-LLM.git
git push -u origin main
```

HTTPS 不需要 SSH 密钥或 GitHub CLI。若要求输入 Password，应使用 GitHub 访问令牌，
或由本机已有凭据管理器完成认证。令牌必须具有本仓库的代码和工作流写权限；
不要在聊天、文档或远端 URL 中填写令牌。本机推送准备使用内存凭据缓存，
不把令牌写入导出的源码目录。

`.github/workflows/docker.yml` 在默认分支 push、`v*` 标签或手动触发时构建，
先实际运行 smoke，只有通过后才发布 GHCR。PR 只构建验证。
发布使用 GitHub 自带的 `GITHUB_TOKEN` 和 `packages: write`，无需存入个人 API Key。
包的公开/私有状态由 GHCR 设置控制，本配置不会主动改为公开。

发布成功后，新机器可以执行：

```bash
git clone https://github.com/EMT52/XSS-Detector-Based-on-LLM.git
cd XSS-Detector-Based-on-LLM
docker compose pull
docker compose up -d --no-build
```

私有镜像需要先使用有读取权限的 GitHub 身份登录 GHCR。
严格复现时同时记录源码 Git commit，并在 `.env` 将 `XSS_IMAGE` 设置为实际发布的
`ghcr.io/emt52/xss-detector-based-on-llm@sha256:实际镜像摘要`。
如果使用 LLM，跨批次的模型输出仍可能变化，固定容器不保证结果完全相同。

## 官方参考

- [Docker 目录挂载](https://docs.docker.com/engine/storage/bind-mounts/)
- [Docker Desktop WSL2 文件系统建议](https://docs.docker.com/desktop/features/wsl/best-practices/)
- [GitHub Actions 发布容器镜像](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)
