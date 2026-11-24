# TChecker 编译指南

本指南说明如何编译缺失的 Java 类文件、下载依赖以及修复代码问题。

## 问题描述

运行 `tools.php.ast2cpg.Main` 时，发现 `bin` 目录下缺少编译好的类文件。源代码位于 `projects/extensions` 目录下，需要手动编译。

## 前置要求

- Java JDK 11 或更高版本
- 网络连接（用于下载依赖）

## 步骤 1: 下载缺失的依赖

项目需要 `antlr4-runtime` 库，但项目中没有包含。需要手动下载：

```bash
# 创建 lib 目录（如果不存在）
mkdir -p lib

# 下载 antlr4-runtime-4.5.3.jar
curl -L -o lib/antlr4-runtime-4.5.3.jar \
  "https://repo1.maven.org/maven2/com/tunnelvisionlabs/antlr4-runtime/4.5.3/antlr4-runtime-4.5.3.jar"
```

或者使用 wget：

```bash
wget -O lib/antlr4-runtime-4.5.3.jar \
  "https://repo1.maven.org/maven2/com/tunnelvisionlabs/antlr4-runtime/4.5.3/antlr4-runtime-4.5.3.jar"
```

## 步骤 2: 修复代码问题

在编译之前，需要修复以下代码问题：

### 2.1 处理 StaticAnalysis1.java

文件位置：`projects/extensions/joern-php/src/main/java/tools/php/ast2cpg/StaticAnalysis1.java`

**问题**：类名与文件名不匹配，构造函数名也需要修改。但该文件未被项目使用（`Main.java` 使用的是 `StaticAnalysis`）。

**推荐方法（更简单）**：直接删除该文件，因为它未被使用：

```bash
rm projects/extensions/joern-php/src/main/java/tools/php/ast2cpg/StaticAnalysis1.java
```

**替代方法**：如果需要保留该文件，可以修复代码：

1. 将第 34 行的类名从 `StaticAnalysis` 改为 `StaticAnalysis1`：
```java
// 修改前
public class StaticAnalysis  {

// 修改后
public class StaticAnalysis1  {
```

2. 将第 60 行的构造函数名从 `StaticAnalysis` 改为 `StaticAnalysis1`：
```java
// 修改前
public StaticAnalysis() {

// 修改后
public StaticAnalysis1() {
```

### 2.2 修复 PHPCSVEdgeInterpreter.java

文件位置：`projects/extensions/joern-php/src/main/java/tools/php/ast2cpg/PHPCSVEdgeInterpreter.java`

**问题**：`repairs` 变量被注释掉了，但代码中仍在使用。

**修复方法**：

将第 129 行的注释取消：
```java
// 修改前
//public static List<String> repairs = Arrays.asList(new String[] {"md5", "addslashes", "mysqli_real_escape_string", "mysql_escape_string"});

// 修改后
public static List<String> repairs = Arrays.asList(new String[] {"md5", "addslashes", "mysqli_real_escape_string", "mysql_escape_string"});
```

## 步骤 3: 编译源代码

### 3.1 设置类路径

编译时需要包含以下依赖：
- `bin` 目录（编译输出目录）
- `lib/antlr4-runtime-4.5.3.jar`（新下载的依赖）
- Apache Commons 库（项目已包含）

### 3.2 编译命令

```bash
cd /path/to/TChecker

# 设置类路径
CLASSPATH="./bin:lib/antlr4-runtime-4.5.3.jar:ApacheCommons/commons-cli-1.4/commons-cli-1.4.jar:ApacheCommons/commons-csv-1.8-bin/commons-csv-1.8/commons-csv-1.8.jar:ApacheCommons/commons-lang3-3.10/commons-lang3-3.10.jar:ApacheCommons/json-20190722.jar"

# 编译所有源代码
javac -d ./bin \
  -cp "$CLASSPATH" \
  -sourcepath "projects/extensions/jpanlib/src/main/java:projects/extensions/joern-php/src/main/java" \
  $(find projects/extensions/jpanlib/src/main/java projects/extensions/joern-php/src/main/java -name "*.java")
```

### 3.3 验证编译结果

编译成功后，检查 Main 类是否已生成：

```bash
find bin -name "Main.class" -path "*/tools/php/ast2cpg/*"
```

应该输出：`bin/tools/php/ast2cpg/Main.class`

## 步骤 4: 运行程序

编译完成后，可以使用以下命令运行程序：

```bash
java -Xmx8G \
  -cp "./bin:lib/antlr4-runtime-4.5.3.jar:ApacheCommons/commons-cli-1.4/commons-cli-1.4.jar:ApacheCommons/commons-csv-1.8-bin/commons-csv-1.8/commons-csv-1.8.jar:ApacheCommons/commons-lang3-3.10/commons-lang3-3.10.jar:ApacheCommons/json-20190722.jar" \
  tools.php.ast2cpg.Main TargetPHPApplication
```

**注意**：程序需要当前目录下存在以下 CSV 文件：
- `nodes.csv` - PHP AST 节点数据（Tab 分隔）
- `rels.csv` - PHP AST 边数据（Tab 分隔）

这些文件通常由 `phpjoern` 的 `php2ast` 工具从 PHP 源代码生成。

## 依赖说明

### 已包含的依赖

项目 `ApacheCommons` 目录下已包含：
- `commons-cli-1.4.jar` - 命令行参数解析
- `commons-csv-1.8.jar` - CSV 文件处理
- `commons-lang3-3.10.jar` - Apache Commons Lang 工具库
- `json-20190722.jar` - JSON 处理

### 需要下载的依赖

- `antlr4-runtime-4.5.3.jar` - ANTLR4 运行时库（用于 `jpanlib` 项目）

下载地址：
```
https://repo1.maven.org/maven2/com/tunnelvisionlabs/antlr4-runtime/4.5.3/antlr4-runtime-4.5.3.jar
```

## 项目结构

```
TChecker/
├── bin/                          # 编译输出目录
│   └── tools/
│       └── php/
│           └── ast2cpg/
│               └── Main.class    # 编译后的主类
├── lib/                          # 外部依赖目录
│   └── antlr4-runtime-4.5.3.jar # 需要下载的依赖
├── ApacheCommons/                # Apache Commons 库
├── projects/
│   └── extensions/
│       ├── jpanlib/              # 基础库（需要先编译）
│       │   └── src/main/java/
│       └── joern-php/            # PHP 扩展（依赖 jpanlib）
│           └── src/main/java/
│               └── tools/
│                   └── php/
│                       └── ast2cpg/
│                           ├── Main.java
│                           ├── StaticAnalysis1.java  # 需要修复
│                           └── PHPCSVEdgeInterpreter.java  # 需要修复
└── nodes.csv                     # 输入文件（需要准备）
└── rels.csv                      # 输入文件（需要准备）
```

## 常见问题

### Q: 编译时出现 "package org.antlr.v4.runtime does not exist" 错误

**A**: 确保已下载 `antlr4-runtime-4.5.3.jar` 并添加到类路径中。

### Q: 编译时出现类名不匹配错误

**A**: 检查是否已修复 `StaticAnalysis1.java` 中的类名和构造函数名。

### Q: 编译时出现 "cannot find symbol: variable repairs" 错误

**A**: 检查是否已取消注释 `PHPCSVEdgeInterpreter.java` 中的 `repairs` 变量。

### Q: 运行时出现 "FileNotFoundException: nodes.csv"

**A**: 确保当前目录下有 `nodes.csv` 和 `rels.csv` 文件。这些文件需要由 `phpjoern` 工具生成。

### Q: 运行时出现 "NoSuchElementException: No more CSV records available"

**A**: CSV 文件可能为空或格式不正确。确保文件至少包含标题行，并且使用 Tab 分隔符。

## 快速开始脚本

可以创建一个脚本来自动化整个过程：

```bash
#!/bin/bash
# compile.sh - 自动化编译脚本

set -e

echo "步骤 1: 下载依赖..."
mkdir -p lib
if [ ! -f "lib/antlr4-runtime-4.5.3.jar" ]; then
    echo "下载 antlr4-runtime-4.5.3.jar..."
    curl -L -o lib/antlr4-runtime-4.5.3.jar \
      "https://repo1.maven.org/maven2/com/tunnelvisionlabs/antlr4-runtime/4.5.3/antlr4-runtime-4.5.3.jar"
else
    echo "antlr4-runtime-4.5.3.jar 已存在，跳过下载"
fi

echo "步骤 2: 修复代码..."
# 这里可以添加自动修复代码的逻辑，或者手动修复后运行脚本

echo "步骤 3: 编译源代码..."
CLASSPATH="./bin:lib/antlr4-runtime-4.5.3.jar:ApacheCommons/commons-cli-1.4/commons-cli-1.4.jar:ApacheCommons/commons-csv-1.8-bin/commons-csv-1.8/commons-csv-1.8.jar:ApacheCommons/commons-lang3-3.10/commons-lang3-3.10.jar:ApacheCommons/json-20190722.jar"

javac -d ./bin \
  -cp "$CLASSPATH" \
  -sourcepath "projects/extensions/jpanlib/src/main/java:projects/extensions/joern-php/src/main/java" \
  $(find projects/extensions/jpanlib/src/main/java projects/extensions/joern-php/src/main/java -name "*.java")

echo "编译完成！"
echo "Main.class 位置: $(find bin -name "Main.class" -path "*/tools/php/ast2cpg/*")"
```

## 参考

- [ANTLR4 Runtime Maven Repository](https://mvnrepository.com/artifact/com.tunnelvisionlabs/antlr4-runtime/4.5.3)
- [Apache Commons CSV](https://commons.apache.org/proper/commons-csv/)
- [phpjoern Documentation](https://github.com/joernio/phpjoern)
