package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// JavaProcess 一个 Java 进程的关键信息
type JavaProcess struct {
	PID     int
	Cmdline []string
	Exe     string
	Cwd     string
	Environ map[string]string
}

// findJavaProcesses 遍历 /proc 找出所有 Java 进程（纯 Go，不依赖 ps/pgrep）。
func findJavaProcesses(rep *Report) []JavaProcess {
	var procs []JavaProcess
	entries, err := os.ReadDir("/proc")
	if err != nil {
		rep.note("无法读取 /proc: %v（非 Linux 或权限不足，进程排查将跳过）", err)
		return procs
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		args := readCmdline(pid)
		if len(args) == 0 {
			continue
		}
		if !isJavaCmdline(args) {
			continue
		}
		p := JavaProcess{
			PID:     pid,
			Cmdline: args,
			Exe:     readLink(filepath.Join("/proc", e.Name(), "exe")),
			Cwd:     readLink(filepath.Join("/proc", e.Name(), "cwd")),
			Environ: readEnviron(pid),
		}
		procs = append(procs, p)
	}
	return procs
}

func isJavaCmdline(args []string) bool {
	if len(args) == 0 {
		return false
	}
	base := filepath.Base(args[0])
	if base == "java" || base == "javaw" || strings.HasSuffix(base, "/java") {
		return true
	}
	// 部分场景 exe 名不是 java（如 wrapper），根据参数判断
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-Dcatalina.base") || strings.Contains(joined, "org.apache.catalina") ||
		strings.Contains(joined, "com.caucho.server.resin.Resin") || strings.Contains(joined, "-Dspring") {
		return true
	}
	return false
}

func readCmdline(pid int) []string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(data) == 0 {
		return nil
	}
	parts := strings.Split(string(data), "\x00")
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readEnviron(pid int) map[string]string {
	m := map[string]string{}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return m
	}
	for _, kv := range strings.Split(string(data), "\x00") {
		if kv == "" {
			continue
		}
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

func readLink(p string) string {
	if t, err := os.Readlink(p); err == nil {
		return t
	}
	return ""
}

// checkProcesses 对应手册第一阶段 [1]-[5]：确认 Java 进程、检查可疑启动参数/环境变量。
func checkProcesses(rep *Report, procs []JavaProcess) {
	const phase = "阶段一 · Java 进程与启动参数"
	if len(procs) == 0 {
		rep.addf(SevInfo, phase, "process", "未发现运行中的 Java 进程",
			"", "若目标应确有 Java 服务，确认是否以其他用户/容器命名空间运行。")
		return
	}
	for _, p := range procs {
		rep.addf(SevInfo, phase, "process",
			"发现 Java 进程 PID="+strconv.Itoa(p.PID),
			"cwd="+p.Cwd, "",
			"启动命令: %s", truncate(strings.Join(p.Cmdline, " "), 400))

		// -javaagent / -agentpath / -agentlib
		for _, arg := range p.Cmdline {
			checkAgentArg(rep, phase, p.PID, arg, "启动参数")
			if strings.HasPrefix(arg, "-Xbootclasspath") {
				rep.addf(SevHigh, phase, "process",
					"检测到 -Xbootclasspath（可替换引导类加载器路径，植入底层恶意代码）",
					arg, "核实该路径是否为业务所需，非预期即高度可疑。")
			}
		}

		// 环境变量注入 JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / JAVA_OPTS
		for _, key := range []string{"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JAVA_OPTS", "CATALINA_OPTS"} {
			if v, ok := p.Environ[key]; ok && v != "" {
				if strings.Contains(v, "-javaagent") || strings.Contains(v, "-agentpath") || strings.Contains(v, "-agentlib") {
					rep.addf(SevCritical, phase, "process",
						"环境变量 "+key+" 中注入了 Java Agent",
						key+"="+v,
						"典型恶意注入手法，定位并删除该 agent jar，清理该环境变量来源(profile/systemd/启动脚本)。")
				} else {
					rep.addf(SevLow, phase, "process",
						"环境变量 "+key+" 已设置（需人工确认内容）",
						key+"="+truncate(v, 300), "确认是否为业务正常配置。")
				}
			}
		}

		// 打开的 fd 中 (deleted) 的 jar/class（对应 [5]）
		checkDeletedFDs(rep, phase, p.PID)
	}
}

func checkAgentArg(rep *Report, phase string, pid int, arg, where string) {
	lower := strings.ToLower(arg)
	if !strings.HasPrefix(arg, "-javaagent") && !strings.HasPrefix(arg, "-agentpath") && !strings.HasPrefix(arg, "-agentlib") {
		return
	}
	// 常见 APM/合法 agent 关键字白名单
	apm := []string{"skywalking", "pinpoint", "elastic-apm", "elasticapm", "opentelemetry", "otel",
		"jacoco", "arthas", "jmx_prometheus", "jolokia", "newrelic", "datadog", "dd-java-agent",
		"glowroot", "uavstack", "byte-buddy-agent"}
	isAPM := false
	for _, a := range apm {
		if strings.Contains(lower, a) {
			isAPM = true
			break
		}
	}
	sev := SevCritical
	advice := "Agent 型内存马可修改任意类字节码。核实该 jar 来源，非预期即删除并从启动脚本/环境变量清除 -javaagent。"
	if isAPM {
		sev = SevMedium
		advice = "疑似 APM/诊断工具 agent，确认其 jar 路径与来源可信；仍建议核对文件签名与修改时间。"
	}
	rep.addf(sev, phase, "process",
		"检测到 Java Agent 参数（PID "+strconv.Itoa(pid)+", 来自"+where+"）",
		arg, advice)
	// 若能提取路径，交由磁盘检查复核修改时间
	if path := agentJarPath(arg); path != "" {
		inspectAgentJar(rep, phase, path)
	}
}

func agentJarPath(arg string) string {
	// -javaagent:/path/to.jar=opts
	idx := strings.IndexByte(arg, ':')
	if idx < 0 {
		return ""
	}
	rest := arg[idx+1:]
	if eq := strings.IndexByte(rest, '='); eq >= 0 {
		rest = rest[:eq]
	}
	return rest
}

func inspectAgentJar(rep *Report, phase, path string) {
	fi, err := os.Stat(path)
	if err != nil {
		rep.addf(SevMedium, phase, "process",
			"Agent jar 路径无法访问（可能已删除但仍被进程持有）",
			path, "结合 /proc/PID/fd 排查 (deleted) 句柄。")
		return
	}
	inTmp := strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/dev/shm/") || strings.HasPrefix(path, "/var/tmp/")
	sev := SevHigh
	if inTmp {
		sev = SevCritical
	}
	rep.addf(sev, phase, "process",
		"Agent jar 文件信息",
		path+"  size="+strconv.FormatInt(fi.Size(), 10)+"  mtime="+fi.ModTime().Format("2006-01-02 15:04:05"),
		"位于 /tmp、/dev/shm 等临时目录的 agent 极可疑；核对修改时间是否落在入侵窗口。")
}

func checkDeletedFDs(rep *Report, phase string, pid int) {
	fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		target := readLink(filepath.Join(fdDir, e.Name()))
		if target == "" {
			continue
		}
		// 跳过本工具自身释放的临时 agent/结果文件（attach 后删除，JVM 仍持句柄），避免自我误报
		if strings.Contains(target, ".memcheck-agent-") || strings.Contains(target, ".memcheck-res-") {
			continue
		}
		if strings.Contains(target, "(deleted)") &&
			(strings.HasSuffix(strings.TrimSuffix(target, " (deleted)"), ".jar") ||
				strings.HasSuffix(strings.TrimSuffix(target, " (deleted)"), ".class")) {
			rep.addf(SevHigh, phase, "process",
				"进程持有已删除的 jar/class 文件句柄（(deleted)）",
				"PID "+strconv.Itoa(pid)+" -> "+target,
				"攻击者常删文件但保留内存加载；可 cat /proc/"+strconv.Itoa(pid)+"/fd/"+e.Name()+" 取证。")
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(截断)"
}
