package main

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// checkJVMTools 对应手册第五/六阶段：Arthas 需交互式 + U 盘拷入，无法自动化；
// 这里用 JDK 自带的 jstack/jmap/jps（若存在）做等效的只读检测。
func checkJVMTools(rep *Report, procs []JavaProcess) {
	const phase = "阶段五 · JVM 运行时检测(JDK 工具)"

	jstack := findTool(procs, "jstack")
	jmap := findTool(procs, "jmap")

	if jstack == "" && jmap == "" {
		rep.addf(SevInfo, phase, "jvm",
			"未找到 jstack/jmap（JDK 诊断工具）",
			"", "内存马运行时检测最精准的方式是 Arthas: 断网时用 U 盘拷入 arthas-boot.jar，"+
				"执行 sc -d *Filter* / *EdwardsiidaeFilter* / *PlasmodesmaFilter* / *Prepupa* 并查 codeSource。")
		return
	}

	for _, p := range procs {
		if jstack != "" {
			scanJStack(rep, phase, jstack, p.PID)
		}
		if jmap != "" {
			scanJMapHisto(rep, phase, jmap, p.PID)
		}
	}
	rep.note("JVM 运行时检测基于 JDK 工具，覆盖度低于 Arthas；如条件允许请用 Arthas 复核 codeSource/classLoader。")
}

// findTool 优先用与目标进程同一 JDK 的工具（由 java 可执行文件推导），否则用 PATH。
func findTool(procs []JavaProcess, tool string) string {
	for _, p := range procs {
		if p.Exe == "" {
			continue
		}
		// exe 形如 /usr/lib/jvm/.../bin/java
		if i := strings.LastIndex(p.Exe, "/bin/"); i >= 0 {
			cand := p.Exe[:i+len("/bin/")] + tool
			if fileExists(cand) {
				return cand
			}
		}
	}
	if path, err := exec.LookPath(tool); err == nil {
		return path
	}
	return ""
}

func runTool(bin string, timeout time.Duration, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", false
	}
	if err != nil && len(out) == 0 {
		return "", false
	}
	return string(out), true
}

// scanJStack 对应 [41]/[42]：线程堆栈中搜索已知恶意类名与代理线程特征。
func scanJStack(rep *Report, phase, jstack string, pid int) {
	out, ok := runTool(jstack, 25*time.Second, "-l", strconv.Itoa(pid))
	if !ok {
		// jstack 失败常因权限（需与目标进程同用户），提示
		rep.note("jstack 连接 PID %d 失败（通常需与目标进程同一用户；可 sudo -u <appuser> 重试）。", pid)
		return
	}
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if desc, ok := matchKnownMalware(line); ok {
			ctxSnip := snippet(lines, i, 4)
			rep.addf(SevCritical, phase, "jvm",
				"jstack 线程堆栈命中已知内存马: "+desc+"（PID "+strconv.Itoa(pid)+"）",
				strings.TrimSpace(line), "运行时已加载该恶意类，按手册定位注入器/codeSource 后清除并重启。\n"+ctxSnip)
			continue
		}
		// 代理线程特征: Socket.connect + 可疑守护线程
		if strings.Contains(line, "Socket.connect") || strings.Contains(line, "SocksSocketImpl") {
			ctxSnip := snippet(lines, i, 3)
			if strings.Contains(ctxSnip, "Prepupa") {
				rep.addf(SevHigh, phase, "jvm",
					"jstack 中发现疑似代理隧道线程（Socket.connect + Prepupa）",
					strings.TrimSpace(line), "代理隧道马特征，结合网络连接排查确认。\n"+ctxSnip)
			}
		}
	}
}

// scanJMapHisto 对应 [40]：直方图中查找 Filter/Servlet/Listener 类实例。
func scanJMapHisto(rep *Report, phase, jmap string, pid int) {
	out, ok := runTool(jmap, 40*time.Second, "-histo:live", strconv.Itoa(pid))
	if !ok {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		low := strings.ToLower(line)
		if !strings.Contains(low, "filter") && !strings.Contains(low, "servlet") &&
			!strings.Contains(low, "listener") && !strings.Contains(low, "valve") {
			continue
		}
		// 直方图行格式:  num  #instances  #bytes  class name
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		cls := fields[len(fields)-1]
		if desc, ok := matchKnownMalware(cls); ok {
			rep.addf(SevCritical, phase, "jvm",
				"jmap 直方图命中已知内存马类: "+desc+"（PID "+strconv.Itoa(pid)+"）",
				cls, "运行时存在该类实例，属真实注入。")
			continue
		}
		if reason, susp := looksSuspiciousClassName(strings.TrimPrefix(cls, "class ")); susp {
			rep.addf(SevHigh, phase, "jvm",
				"jmap 直方图中可疑组件类: "+reason+"（PID "+strconv.Itoa(pid)+"）",
				cls, "非框架/无包名的 Filter/Servlet 类，人工用 Arthas jad 反编译确认。")
		}
	}
}

func snippet(lines []string, idx, radius int) string {
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + radius
	if end >= len(lines) {
		end = len(lines) - 1
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		b.WriteString("      | ")
		b.WriteString(strings.TrimRight(lines[i], " \t"))
		if i < end {
			b.WriteString("\n")
		}
	}
	return b.String()
}
