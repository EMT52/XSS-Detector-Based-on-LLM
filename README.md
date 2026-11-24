# XSS Detector Based on LLM

现有 PHP → AST → TChecker → Neo4j → PUT → 浏览器验证实验项目。

Docker 镜像只提供固定的运行依赖，实验代码和应用不打进镜像。
`XSS/` 下的文件全部留在宿主机，待测应用放到 `php-app/`。
容器挂载当前项目目录，保存代码后可以重新运行；Java 修改会自动触发编译。
Windows 使用 Docker Desktop 的 WSL2 后端及 Linux containers。

详细步骤、依赖版本、密钥传入、GHCR 发布和验证范围见
[Docker 使用说明](Docker使用说明.md)。原本机流程见 [scripts/操作手册.md](scripts/操作手册.md)。

```bash
docker compose build
docker compose up -d
docker compose exec --user xss lab xss check
docker compose exec --user xss lab xss prepare
docker compose exec --user xss lab xss fuzz --output output/php-app.json
```

默认镜像使用普通 PHP 7.0.33。原仓库的插桩 PHP 源码缺失，因此普通镜像不构成
对 sanitizer feedback 插桩机制的完整复现。CI 只有通过本地端到端检查后才发布镜像；
该检查不调用 LLM，也不验证插桩反馈。

第三方工具及其许可证保留在各自目录：`TChecker/`、`phpjoern/`。
原有 llm-xss 项目说明见 [llm-xss/README.md](llm-xss/README.md)。
