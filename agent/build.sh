#!/bin/sh
# 编译 MemCheckAgent 为 agent.jar（供 Go 侧 go:embed 内嵌）。
# 需要 JDK(javac/jar)。目标字节码版本设为 8 以兼容线上老 JVM。
set -eu
cd "$(dirname "$0")"
rm -rf build
mkdir -p build
javac -source 8 -target 8 -d build MemCheckAgent.java
jar cfm agent.jar MANIFEST.MF -C build MemCheckAgent.class
rm -rf build
echo "built $(pwd)/agent.jar"
