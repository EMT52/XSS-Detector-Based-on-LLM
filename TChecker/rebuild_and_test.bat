@echo off
REM TChecker 重新编译和测试脚本 (Windows)

echo === 开始重新编译 TChecker ===
echo.

cd /d "%~dp0"

REM 设置 JAVA_HOME
set JAVA_HOME=C:\Program Files\Java\jdk-11
set PATH=%JAVA_HOME%\bin;%PATH%

REM 清理旧的编译文件
echo 清理旧的编译文件...
if exist "bin\tools\php\ast2cpg\StaticAnalysis.class" (
    del /Q "bin\tools\php\ast2cpg\StaticAnalysis.class"
)

REM 重新编译
echo 重新编译 StaticAnalysis.java...
javac -encoding UTF-8 -cp "./bin;ApacheCommons/commons-cli-1.4/commons-cli-1.4.jar;ApacheCommons/commons-csv-1.8-bin/commons-csv-1.8/commons-csv-1.8.jar;ApacheCommons/commons-lang3-3.10/commons-lang3-3.10.jar;ApacheCommons/json-20190722.jar" -d bin projects/extensions/joern-php/src/main/java/tools/php/ast2cpg/StaticAnalysis.java

if %ERRORLEVEL% EQU 0 (
    echo ✓ 编译成功！
) else (
    echo ✗ 编译失败！
    pause
    exit /b 1
)

echo.
echo === 编译完成 ===
echo.
echo 现在可以在虚拟机上运行测试了
echo.

pause
