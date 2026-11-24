# 可选的本机 wheel 缓存

此目录可保存与 `docker/requirements.lock` 匹配的 Python wheel，减少重复下载。
wheel 不上传 GitHub，也不会作为独立文件层留在运行镜像中；构建时只读挂载。
默认仍可从 PyPI 下载。所有锁定依赖及 pip/setuptools/wheel 已缓存时，可给
`docker build` 增加 `--build-arg XSS_OFFLINE_WHEELS=1` 禁止该安装步骤联网。

本次本机缓存复用了现有环境中的 wheel/UV 缓存；重新打包前检查原始 RECORD
中的文件哈希、大小，以及 wheel 的 Python/平台兼容标签，保持依赖版本不变。
