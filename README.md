# XSS Detector Based on LLM

现有 PHP → AST → TChecker → Neo4j → PUT → 浏览器验证实验项目。

Docker 镜像只提供固定的运行依赖，实验代码和应用不打进镜像。
`XSS/` 下的文件全部留在宿主机，待测应用放到 `php-app/`。
容器挂载当前项目目录，保存代码后可以重新运行；Java 修改会自动触发编译。
Windows 使用 Docker Desktop 的 WSL2 后端及 Linux containers。

操作说明集中在 [操作/](操作/README.md)。详细步骤、依赖版本、密钥传入、GHCR 发布和验证范围见
[Docker 使用说明](操作/Docker使用说明.md)。原本机流程见 [一键准备操作手册](操作/操作手册.md)。

```bash
# 宿主机：使用已经发布的镜像，不在新机器编译
./进入环境.sh --pull

# 已进入容器 Bash，以下都是普通命令，可逐条执行、修改和调试
pwd
python --version
php --version
cd phpjoern
./php2ast /workspace/XSS/php-app
```

容器终端支持任意命令，不会在进入时自动跑实验。步骤 1～7 的逐条命令见
[容器内手动实验](操作/手动实验.md)。再次进入只需 `./进入环境.sh`；
`exit` 退出终端，源码与输出仍保存在宿主机。需要批量准备时也可手动执行
`./prepare_step7.sh`，随后自行运行 `python PUT_fuzzer.py`。

默认镜像使用普通 PHP 7.0.33。原仓库的插桩 PHP 源码缺失，因此普通镜像不构成
对 sanitizer feedback 插桩机制的完整复现。CI 只有通过本地端到端检查后才发布镜像；
该检查不调用 LLM，也不验证插桩反馈。

第三方工具及其许可证保留在各自目录：`TChecker/`、`phpjoern/`。
原有 llm-xss 项目说明见 [llm-xss/README.md](llm-xss/README.md)。
