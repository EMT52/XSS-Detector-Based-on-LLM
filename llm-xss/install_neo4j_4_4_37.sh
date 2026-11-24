#!/usr/bin/env bash
set -euo pipefail

NEO4J_VERSION="4.4.37"
NEO4J_ARCHIVE="neo4j-community-${NEO4J_VERSION}-unix.tar.gz"
NEO4J_URL="https://dist.neo4j.org/${NEO4J_ARCHIVE}"
NEO4J_SHA256="1df748bf54206d4cbf2c9e19bab9c43120df054f466469c93099afd41c3f2cd8"
NEO4J_HOME="/opt/neo4j"
JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-1}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATABASES_DIR="${PROJECT_ROOT}/PUT_extractor/databases"
EMBEDDED_HOME="${DATABASES_DIR}/php-app"

if [[ "${EUID}" -ne 0 ]]; then
    echo "请使用 sudo 运行：sudo bash ${PROJECT_ROOT}/install_neo4j_4_4_37.sh" >&2
    exit 1
fi

INSTALL_USER="${SUDO_USER:-}"
if [[ -z "${INSTALL_USER}" || "${INSTALL_USER}" == "root" ]]; then
    INSTALL_USER="$(stat -c '%U' "${PROJECT_ROOT}")"
fi
INSTALL_GROUP="$(id -gn "${INSTALL_USER}")"

if [[ -e "${NEO4J_HOME}" ]]; then
    echo "${NEO4J_HOME} 已存在；为避免覆盖，安装已停止。" >&2
    exit 1
fi

if [[ -e "${EMBEDDED_HOME}" ]]; then
    echo "${EMBEDDED_HOME} 已存在；为避免覆盖，安装已停止。" >&2
    exit 1
fi

echo "[1/7] 安装 OpenJDK 11 和下载工具"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-11-jre-headless curl ca-certificates

if [[ ! -x "${JAVA_HOME}/bin/java" ]]; then
    echo "Java 11 安装后仍未出现在 ${JAVA_HOME}" >&2
    exit 1
fi

TEMP_DIR="$(mktemp -d /tmp/neo4j-install.XXXXXX)"
cleanup() {
    if [[ "${TEMP_DIR}" == /tmp/neo4j-install.* && -d "${TEMP_DIR}" ]]; then
        find "${TEMP_DIR}" -depth -delete
    fi
}
trap cleanup EXIT

echo "[2/7] 下载 Neo4j Community ${NEO4J_VERSION}"
curl -fL --retry 5 --retry-delay 2 \
    -o "${TEMP_DIR}/${NEO4J_ARCHIVE}" "${NEO4J_URL}"

echo "[3/7] 校验 Neo4j 安装包"
printf '%s  %s\n' "${NEO4J_SHA256}" "${TEMP_DIR}/${NEO4J_ARCHIVE}" | sha256sum --check --status

echo "[4/7] 安装到 ${NEO4J_HOME}"
tar -xzf "${TEMP_DIR}/${NEO4J_ARCHIVE}" -C /opt
mv "/opt/neo4j-community-${NEO4J_VERSION}" "${NEO4J_HOME}"
chown -R "${INSTALL_USER}:${INSTALL_GROUP}" "${NEO4J_HOME}"

cat >> "${NEO4J_HOME}/conf/neo4j.conf" <<'EOF'

# llm-xss local embedded Neo4j settings
dbms.default_listen_address=127.0.0.1
dbms.connector.http.enabled=true
dbms.connector.http.listen_address=:7474
dbms.connector.bolt.enabled=true
dbms.connector.bolt.listen_address=:7687
dbms.default_database=neo4j
dbms.memory.heap.initial_size=512m
dbms.memory.heap.max_size=1g
dbms.memory.pagecache.size=512m
EOF
chown "${INSTALL_USER}:${INSTALL_GROUP}" "${NEO4J_HOME}/conf/neo4j.conf"

echo "[5/7] 设置初始密码并启动自检"
runuser -u "${INSTALL_USER}" -- env JAVA_HOME="${JAVA_HOME}" \
    "${NEO4J_HOME}/bin/neo4j-admin" set-initial-password "${NEO4J_PASSWORD}"
runuser -u "${INSTALL_USER}" -- env JAVA_HOME="${JAVA_HOME}" \
    "${NEO4J_HOME}/bin/neo4j" start

READY=0
for _ in $(seq 1 60); do
    if curl -fsS -u "neo4j:${NEO4J_PASSWORD}" "http://127.0.0.1:7474/" >/dev/null; then
        READY=1
        break
    fi
    sleep 1
done

if [[ "${READY}" -ne 1 ]]; then
    echo "Neo4j 未能在 60 秒内就绪，最后 80 行日志如下：" >&2
    tail -n 80 "${NEO4J_HOME}/logs/neo4j.log" >&2 || true
    exit 1
fi

echo "[6/7] 停止主实例并创建项目嵌入式副本"
runuser -u "${INSTALL_USER}" -- env JAVA_HOME="${JAVA_HOME}" \
    "${NEO4J_HOME}/bin/neo4j" stop
install -d -o "${INSTALL_USER}" -g "${INSTALL_GROUP}" "${DATABASES_DIR}"
cp -a "${NEO4J_HOME}" "${EMBEDDED_HOME}"
chown -R "${INSTALL_USER}:${INSTALL_GROUP}" "${EMBEDDED_HOME}"

echo "[7/7] 安装完成"
echo "Java: $(${JAVA_HOME}/bin/java -version 2>&1 | head -n 1)"
echo "Neo4j: $(runuser -u "${INSTALL_USER}" -- env JAVA_HOME="${JAVA_HOME}" "${NEO4J_HOME}/bin/neo4j" --version)"
echo "嵌入式目录: ${EMBEDDED_HOME}"
echo "注意：当前是可启动的空库副本。完成指导书步骤 3 的 CSV 导入后，需要重新执行步骤 4 的复制操作。"
echo "导入图数据并刷新嵌入式副本后，运行提取器时使用："
echo "  cd ${PROJECT_ROOT}/PUT_extractor"
echo "  JAVA_HOME=${JAVA_HOME} python PUT_extractor.py --target=php-app"
