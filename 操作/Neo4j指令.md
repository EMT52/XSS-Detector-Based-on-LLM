# 启动 Neo4j
sudo JAVA_HOME=/home/lgc/jdk-25.0.2 /opt/neo4j/bin/neo4j start
sudo JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 /opt/neo4j/bin/neo4j start


# 停止 Neo4j
sudo JAVA_HOME=/home/lgc/jdk-25.0.2 /opt/neo4j/bin/neo4j stop
sudo JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 /opt/neo4j/bin/neo4j stop

# 重启 Neo4j
sudo JAVA_HOME=/home/lgc/jdk-25.0.2 /opt/neo4j/bin/neo4j restart
sudo JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 /opt/neo4j/bin/neo4j restart


# 查看状态
sudo JAVA_HOME=/home/lgc/jdk-25.0.2 /opt/neo4j/bin/neo4j status
sudo JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 /opt/neo4j/bin/neo4j status

# 查看日志
sudo tail -f /opt/neo4j/logs/neo4j.log

# 前台运行（用于调试）
sudo JAVA_HOME=/home/lgc/jdk-25.0.2 /opt/neo4j/bin/neo4j console
# 按 Ctrl+C 停止

# 判断版本
/opt/neo4j/bin/neo4j --version

# 密码
1


cp -r /opt/neo4j /home/lgc/XSSKy/PUT_extractor/databases
