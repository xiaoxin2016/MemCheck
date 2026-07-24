// MemCheck —— 内存马应急排查自动化工具
//
// 依据《内存马应急排查手册 v2.0》实现的只读检测程序：自动完成 Java 进程/Agent 排查、
// 磁盘注入器扫描、配置篡改检查、网络连接分析、JVM 运行时检测、日志分析与持久化排查，
// 输出带风险等级的排查报告。
//
// 设计原则：
//   - 零第三方依赖，仅用 Go 标准库，单一静态二进制，天然适配 x86_64/ARM64、断网环境。
//   - 只读安全：绝不删除、修改、杀进程或重启任何服务；清除操作交由人工按手册处置。
//   - 尽量原生实现（读 /proc、走文件系统、解析 zip），不强依赖 ps/find/grep/netstat。
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var version = "1.4.0"

func main() {
	var (
		rootFlag = flag.String("root", "", "指定应用根目录，多个用逗号分隔（默认自动定位）")
		full     = flag.Bool("full", false, "从 / 全盘扫描（慢，默认仅扫描定位到的应用目录）")
		days     = flag.Int("days", 30, "近期修改判定的天数阈值")
		timeout  = flag.Duration("timeout", 3*time.Minute, "磁盘扫描总超时")
		jsonOut  = flag.Bool("json", false, "以 JSON 格式输出（便于对接 SIEM/自动化）")
		outFile  = flag.String("o", "", "报告输出到文件（默认标准输出）")
		noColor  = flag.Bool("no-color", false, "禁用终端着色")
		noJVM    = flag.Bool("no-jvm", false, "跳过 JVM 工具(jstack/jmap)运行时检测")
		noNet    = flag.Bool("no-net", false, "跳过网络连接排查")
		showVer  = flag.Bool("version", false, "打印版本并退出")
		maxFile  = flag.Int64("max-file", 512*1024, "读取文件内容的单文件字节上限")
		attachSc = flag.Bool("attach-scan", false, "强制只读运行时枚举（默认已开启；-no-attach 时仍可用它强制开启）")
		noAttach = flag.Bool("no-attach", false, "禁用默认的运行时 attach 枚举，回到纯被动(不接触 JVM)检测")
		remove   = flag.Bool("remove", false, "热卸载模式：枚举运行时过滤器链，交互确认后从内存移除可疑内存马")
		rmClass  = flag.String("remove-class", "", "手工指定要卸载的类名（逗号分隔，隐含开启 -remove）")
		assumeY  = flag.Bool("yes", false, "卸载时跳过交互确认（自动化场景，谨慎使用）")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("memcheck %s\n", version)
		return
	}

	// 输出目标
	out := os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "无法创建输出文件: %v\n", err)
			os.Exit(2)
		}
		defer f.Close()
		out = f
	}
	// 非 TTY 或 --json 或 --no-color 时关闭颜色
	if *noColor || *jsonOut || *outFile != "" || !isTerminal(os.Stdout) {
		disableColor()
	}

	host, _ := os.Hostname()
	rep := &Report{
		Host:      host,
		StartedAt: time.Now().Format("2006-01-02 15:04:05 -0700"),
	}

	if !*jsonOut {
		fmt.Fprintf(os.Stderr, "%s[memcheck]%s 开始排查（只读，不删文件/不杀进程/不重启；默认会 attach JVM 做只读枚举，-no-attach 可关闭）...\n", colCyan, colReset)
	}

	cfg := scanConfig{
		roots:      splitCSV(*rootFlag),
		recentDays: *days,
		maxFile:    *maxFile,
		full:       *full,
		timeout:    *timeout,
	}

	// —— 阶段一：进程与 Agent ——
	procs := findJavaProcesses(rep)
	checkProcesses(rep, procs)

	javaPIDs := map[int]bool{}
	for _, p := range procs {
		javaPIDs[p.PID] = true
	}

	// 定位扫描根目录
	roots := resolveRoots(rep, cfg, procs)

	// —— 阶段二：磁盘注入器 ——
	progress(*jsonOut, "扫描磁盘注入器 (JSP/class/危险代码)...")
	checkDisk(rep, cfg, roots)
	checkSpringBootJars(rep, roots, cfg)

	// —— 阶段三：配置篡改 ——
	progress(*jsonOut, "检查配置文件 (web.xml/server.xml/resin.xml)...")
	checkConfigs(rep, roots, cfg)

	// —— 阶段四：网络 ——
	if !*noNet {
		progress(*jsonOut, "排查网络连接 (/proc/net)...")
		checkNetwork(rep, javaPIDs)
	}

	// —— 阶段五：JVM 运行时 ——
	if !*noJVM {
		progress(*jsonOut, "JVM 运行时检测 (jstack/jmap)...")
		checkJVMTools(rep, procs)
	}

	// —— 阶段七：日志 ——
	progress(*jsonOut, "分析日志...")
	checkLogs(rep, roots, cfg)

	// —— 阶段八：持久化 ——
	progress(*jsonOut, "排查定时任务/启动项/SSH/SUID...")
	checkPersistence(rep, roots, cfg)

	// —— 阶段九：运行时内存马排查 ——
	// 默认即对发现的 JVM 做只读 attach 运行时枚举（内存注入型内存马只能这样发现）；
	// -no-attach 关闭该默认行为；-attach-scan 可在 -no-attach 时强制开启；-remove 则进入卸载。
	removeMode := *remove || *rmClass != ""
	runtimeScan := attachSupported && len(procs) > 0 && !removeMode && (*attachSc || !*noAttach)
	rmOpt := removeOptions{
		enabled:   removeMode || runtimeScan,
		scanOnly:  runtimeScan,
		classes:   splitCSV(*rmClass),
		assumeYes: *assumeY,
	}
	if rmOpt.enabled {
		if rmOpt.scanOnly {
			progress(*jsonOut, "运行时过滤器链枚举 (attach, 只读)...")
		} else {
			progress(*jsonOut, "内存马热卸载 (attach)...")
		}
		runRemoval(rep, procs, rmOpt)
	} else if len(procs) > 0 && attachSupported && *noAttach {
		// 用户用 -no-attach 主动关闭了运行时排查：提醒内存注入型内存马将无法发现
		rep.addf(SevInfo, "阶段九 · 运行时内存马排查(attach)",
			"remove", "已按 -no-attach 跳过运行时排查（发现 "+strconv.Itoa(len(procs))+" 个 Java 进程）",
			"", "反序列化/漏洞一次性注入的内存马只存在于 JVM 内存、磁盘无文件，纯被动检测无法发现。"+
				"去掉 -no-attach（默认即会 attach 只读枚举），或加 -remove 直接枚举并卸载。")
	}

	// 输出
	if *jsonOut {
		if err := rep.printJSON(out); err != nil {
			fmt.Fprintf(os.Stderr, "写 JSON 失败: %v\n", err)
			os.Exit(2)
		}
	} else {
		rep.printText(out)
	}

	os.Exit(exitCode(rep))
}

// exitCode 依据最高风险等级返回退出码，便于脚本/编排判断。
// 0=无异常, 1=有中/低危, 2=有高危/严重。
func exitCode(rep *Report) int {
	c := rep.counts()
	if c[SevCritical] > 0 || c[SevHigh] > 0 {
		return 2
	}
	if c[SevMedium] > 0 || c[SevLow] > 0 {
		return 1
	}
	return 0
}

func progress(jsonOut bool, msg string) {
	if !jsonOut {
		fmt.Fprintf(os.Stderr, "%s[memcheck]%s %s\n", colCyan, colReset, msg)
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// isTerminal 简单判断是否为字符设备（TTY）。
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func usage() {
	fmt.Fprintf(os.Stderr, `memcheck %s —— 内存马应急排查自动化工具（只读检测）

用法:
  memcheck [选项]

说明:
  依据《内存马应急排查手册 v2.0》自动完成 Java 进程、磁盘注入器、配置篡改、
  网络连接、JVM 运行时、日志与持久化的排查，输出带风险等级的报告。
  本工具只读，绝不删除文件/杀进程/重启服务；清除请按手册人工处置。
  建议以 root 运行以获得完整的 /proc 与文件系统可见性。

选项:
  -root string     指定应用根目录，逗号分隔（默认自动定位）
  -full            从 / 全盘扫描（慢）
  -days int        近期修改天数阈值（默认 30）
  -timeout dur     磁盘扫描总超时（默认 3m）
  -json            JSON 输出
  -o string        输出到文件
  -no-color        禁用着色
  -no-jvm          跳过 jstack/jmap 检测
  -no-net          跳过网络排查
  -max-file int    单文件读取上限字节（默认 524288）
  -version         打印版本

运行时排查/热卸载（仅 Linux）:
  （默认）      发现 Java 进程时自动 attach 目标 JVM，只读枚举过滤器链并按 codeSource 报告可疑内存马
  -no-attach       禁用上述默认行为，回到纯被动(不接触 JVM)检测
  -attach-scan     即使用了 -no-attach 也强制做只读运行时枚举
  -remove          枚举运行时过滤器链，交互确认后从内存移除可疑内存马
  -remove-class s  手工指定要卸载的类名（逗号分隔，隐含 -remove）
  -yes             跳过交互确认（自动化场景，谨慎使用）
  说明: 反序列化/漏洞一次性注入的内存马只在 JVM 内存、磁盘无文件，只有 attach 运行时枚举才能发现，
        故默认开启（只读，不改动应用）。卸载只在内存移除注册，不删磁盘文件、不重启。建议 root 运行。

退出码:
  0 未见异常  1 存在中/低危  2 存在高危/严重

示例:
  sudo ./memcheck
  sudo ./memcheck -root /opt/tomcat -days 7
  sudo ./memcheck -json -o /tmp/memcheck.json
  sudo ./memcheck                               # 默认即 attach 只读枚举运行时过滤器链，发现内存注入型内存马
  sudo ./memcheck -no-attach                    # 纯被动检测，不接触任何 JVM
  sudo ./memcheck -remove                       # 枚举并交互式卸载可疑内存马
  sudo ./memcheck -remove-class GodzillaFilter -yes      # 定向卸载指定类
`, version)
}
