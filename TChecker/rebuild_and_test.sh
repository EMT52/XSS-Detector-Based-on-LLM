#!/bin/bash

# TChecker 重新编译和测试脚本

echo "=== 开始重新编译 TChecker ==="

cd "$(dirname "$0")"

# 清理旧的编译文件
echo "清理旧的编译文件..."
rm -rf bin/tools/php/ast2cpg/StaticAnalysis.class

# 重新编译
echo "重新编译 StaticAnalysis.java..."
JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
export JAVA_HOME

# 编译单个文件
javac -cp "./bin:ApacheCommons/commons-cli-1.4/commons-cli-1.4.jar:ApacheCommons/commons-csv-1.8-bin/commons-csv-1.8/commons-csv-1.8.jar:ApacheCommons/commons-lang3-3.10/commons-lang3-3.10.jar:ApacheCommons/json-20190722.jar" \
    -d bin \
    projects/extensions/joern-php/src/main/java/tools/php/ast2cpg/StaticAnalysis.java

if [ $? -eq 0 ]; then
    echo "✓ 编译成功！"
else
    echo "✗ 编译失败！"
    exit 1
fi

# 测试
echo ""
echo "=== 测试修复后的 TChecker ==="
echo ""

# 测试 php-app
if [ -d "/home/lgc/php-app" ]; then
    echo "测试 php-app..."
    java -Xmx8G -cp "./bin:ApacheCommons/commons-cli-1.4/commons-cli-1.4.jar:ApacheCommons/commons-csv-1.8-bin/commons-csv-1.8/commons-csv-1.8.jar:ApacheCommons/commons-lang3-3.10/commons-lang3-3.10.jar:ApacheCommons/json-20190722.jar" \
        tools.php.ast2cpg.Main /home/lgc/php-app
    echo ""
fi

# 测试 try-app
if [ -d "/home/lgc/try-app" ]; then
    echo "测试 try-app..."
    java -Xmx8G -cp "./bin:ApacheCommons/commons-cli-1.4/commons-cli-1.4.jar:ApacheCommons/commons-csv-1.8-bin/commons-csv-1.8/commons-csv-1.8.jar:ApacheCommons/commons-lang3-3.10/commons-lang3-3.10.jar:ApacheCommons/json-20190722.jar" \
        tools.php.ast2cpg.Main /home/lgc/try-app
    echo ""
fi

echo "=== 测试完成 ==="
