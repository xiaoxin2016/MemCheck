# MemCheck — 内存马应急排查自动化工具

依据《内存马应急排查手册 v2.0》实现的 **只读** 自动化排查程序。上机后一条命令即可完成
Java 进程 / Agent 排查、磁盘注入器扫描、配置篡改检查、网络连接分析、JVM 运行时检测、
日志分析与持久化排查，输出带风险等级的排查报告，替代手册中需逐条手工复制执行的几十条命令。

## 设计原则

- **零第三方依赖**：仅使用 Go 标准库，编译为单个静态二进制，天然适配 x86_64 / ARM64、
  国产化环境与断网现场（拷贝二进制即可运行，无需装任何东西）。
- **只读安全**：绝不删除文件、修改配置、杀进程或重启服务。清除操作按手册「四、内存马清除
  操作」由人工在确认后执行——本工具只负责精准定位。
- **原生实现、少依赖外部命令**：直接读 `/proc`、遍历文件系统、用 `archive/zip` 解析 jar、
  解析 `/proc/net/tcp` 得到网络连接，不强依赖 `ps`/`find`/`grep`/`netstat`/`ss`（这些在
  应急现场可能被裁剪或被攻击者替换）。仅在做 JVM 运行时检测时可选调用 JDK 的 `jstack`/`jmap`。

## 覆盖的排查阶段（对照手册）

| 手册阶段 | 本工具实现 |
|---------|-----------|
| 一 · Java 进程与启动参数 (1–5) | 遍历 `/proc` 找 Java 进程，检查 `-javaagent`/`-agentpath`/`-Xbootclasspath`、`JAVA_TOOL_OPTIONS` 等环境变量注入、`(deleted)` 文件句柄 |
| 二 · 磁盘注入器 (6–14) | 原生遍历应用目录，命中已知恶意类名 / 危险关键词的 JSP、非 lib 目录的可疑 `.class`、`work/Catalina` 编译产物、隐藏文件、Spring Boot fat jar 内部类 |
| 三 · 配置篡改 (15–19) | 解析 `web.xml` 的 filter/listener/servlet、`server.xml` 的 Valve、`resin.xml`，比对白名单与已知特征 |
| 四 · 网络连接 (20–23) | 纯 Go 解析 `/proc/net/tcp[6]` 并映射 socket→PID，标记非业务端口的外联/监听，识别内网代理隧道特征 |
| 五/六 · 运行时检测 (24–43) | 调用 JDK `jstack`/`jmap`（若存在）在堆栈/直方图中搜索已知恶意类与代理线程；Arthas 需交互式，给出操作指引 |
| 七 · 日志分析 (44–48) | 定位并分析 access log / catalina.out：WebSocket 升级请求、可疑 POST、类加载异常 |
| 八/九 · 持久化 (49–58) | crontab / cron.d / systemd / rc.local、启动脚本中的 `-javaagent`、`authorized_keys`、非标准目录 SUID |

内置已知内存马特征库（冰蝎 `EdwardsiidaeFilter`、哥斯拉 `PlasmodesmaFilter` 及 5 个载荷组件、
代理马 `Prepupa`）与常见框架 Filter/Servlet 白名单（Spring / Shiro / Druid / Tomcat / Resin），
兼顾检出率与误报控制。

## 构建

```bash
go build -o memcheck .

# 交叉编译（现场为 ARM64 时在本机编好拷过去）
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o memcheck-arm64 .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o memcheck-amd64 .
```

## 使用

```bash
# 自动定位应用目录并全面排查（建议 root 运行以获得完整 /proc 与文件系统可见性）
sudo ./memcheck

# 指定应用根目录、只看近 7 天变更
sudo ./memcheck -root /opt/tomcat -days 7

# 输出 JSON 便于对接 SIEM / 自动化编排
sudo ./memcheck -json -o /tmp/memcheck.json

# 全盘扫描（慢）
sudo ./memcheck -full
```

### 主要参数

| 参数 | 说明 |
|------|------|
| `-root` | 指定应用根目录，逗号分隔（默认自动定位；显式指定后以其为准） |
| `-full` | 从 `/` 全盘扫描（慢） |
| `-days` | 近期修改判定天数阈值（默认 30） |
| `-timeout` | 磁盘扫描总超时（默认 3m） |
| `-json` | JSON 输出 |
| `-o` | 报告写入文件 |
| `-no-jvm` | 跳过 `jstack`/`jmap` 运行时检测 |
| `-no-net` | 跳过网络排查 |
| `-no-color` | 禁用终端着色 |

### 退出码

- `0`：未见异常
- `1`：存在中/低危发现
- `2`：存在高危/严重发现

便于在编排/巡检脚本中直接判断。

## 输出说明

报告按风险等级（严重/高危/中危/低危/信息）排序，每条包含证据（文件路径、大小、修改时间、
连接、命令等）与处置建议，并附手册「六、排查结果判断指南」的 `codeSource` 研判要点与
下一步人工清除指引。

## 注意事项

- 运行时检测（Arthas）最精准但需交互式操作，无法自动化；断网现场请按手册用 U 盘拷入
  `arthas-boot.jar`，用 `sc -d` 查恶意类的 `codeSource`/`classLoader` 定位注入来源。
- `jstack`/`jmap` 通常需与目标 Java 进程 **同一用户** 才能连接，必要时 `sudo -u <appuser>` 运行。
- 本工具用于 **授权范围内** 的应急响应与安全演练。
```
