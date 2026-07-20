package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// agent.jar 由 agent/build.sh 用 JDK 编译产生，通过 go:embed 静态内嵌进二进制，
// 运行时释放到临时文件并 attach 进目标 JVM——满足“引入第三方能力但静态编译进单一二进制”。
//
//go:embed agent/agent.jar
var agentJar []byte

const removePhase = "阶段九 · 内存马热卸载(attach)"

// removeOptions 卸载模式参数
type removeOptions struct {
	enabled   bool
	classes   []string // -remove-class 显式指定的目标类（覆盖自动推荐）
	assumeYes bool     // -yes 跳过交互确认
}

// agentResult / agentItem 与 MemCheckAgent 回写的 JSON 对应
type agentResult struct {
	ContextsFound int         `json:"contextsFound"`
	Action        string      `json:"action"`
	Error         string      `json:"error"`
	Results       []agentItem `json:"results"`
}

type agentItem struct {
	Class        string `json:"class"`
	Status       string `json:"status"`
	RegisteredAs string `json:"registeredAs"`
	Detail       string `json:"detail"`
}

// knownMalwareNames 返回已知内存马类名列表（作为自动扫描/推荐的目标集合）。
func knownMalwareNames() []string {
	names := make([]string, 0, len(KnownMalwareClasses))
	for k := range KnownMalwareClasses {
		names = append(names, k)
	}
	return names
}

// runRemoval 执行内存马热卸载流程：发现候选 -> 交互确认 -> attach 卸载 -> 汇报结果。
func runRemoval(rep *Report, procs []JavaProcess, opt removeOptions) {
	if !attachSupported {
		rep.addf(SevInfo, removePhase, "remove", "当前平台不支持 attach 卸载（仅 Linux）", "", "")
		return
	}
	if len(procs) == 0 {
		rep.addf(SevInfo, removePhase, "remove", "未发现 Java 进程，无可卸载目标", "", "")
		return
	}
	if os.Geteuid() != 0 {
		rep.note("卸载模式建议以 root 运行；非 root 时只能 attach 到同一用户的 JVM。")
	}

	jarPath, cleanup, err := writeAgentJar()
	if err != nil {
		rep.addf(SevMedium, removePhase, "remove", "释放内嵌 agent 失败", err.Error(),
			"检查 /tmp 是否可写。")
		return
	}
	defer cleanup()

	fmt.Fprintf(os.Stderr, "\n%s[memcheck]%s 进入内存马热卸载模式（只在内存移除注册，不改磁盘/不重启）\n", colYellow, colReset)

	for _, p := range procs {
		processOne(rep, p, jarPath, opt)
	}
}

func processOne(rep *Report, p JavaProcess, jarPath string, opt removeOptions) {
	pidStr := strconv.Itoa(p.PID)

	// 预检查可 attach 性（容器隔离等），提前给出清晰提示
	if err := checkAttachable(p.PID); err != nil {
		rep.addf(SevMedium, removePhase, "remove", "PID "+pidStr+" 无法 attach", err.Error(),
			"在对应容器内运行本工具，或改用 Arthas 手工处置。")
		return
	}

	var candidates []string
	if len(opt.classes) > 0 {
		// 手工指定：直接作为候选
		candidates = opt.classes
	} else {
		// 自动模式：先 scan 发现已加载/已注册的已知内存马类
		res, err := runAgent(p.PID, jarPath, "scan", knownMalwareNames())
		if err != nil {
			rep.addf(SevMedium, removePhase, "remove", "PID "+pidStr+" 扫描失败", err.Error(),
				"确认目标为 HotSpot JVM 且权限足够。")
			return
		}
		reportScan(rep, p, res)
		// 推荐卸载“有风险的”——即在注册表中命中的（status=found）
		for _, it := range res.Results {
			if it.Status == "found" {
				candidates = append(candidates, it.Class)
			}
		}
		candidates = dedupStrings(candidates)
	}

	if len(candidates) == 0 {
		rep.addf(SevInfo, removePhase, "remove", "PID "+pidStr+" 未发现可热卸载的已注册内存马类",
			"", "若确认存在内存马但此处未命中，可用 -remove-class 手工指定类名，或用 Arthas 复核。")
		return
	}

	// 交互确认（-yes 跳过）
	if !opt.assumeYes {
		if !confirmRemoval(p, candidates) {
			rep.note("PID %d 用户取消卸载。", p.PID)
			rep.addf(SevInfo, removePhase, "remove", "PID "+pidStr+" 已跳过卸载（用户取消/非交互）",
				strings.Join(candidates, ", "), "如需卸载请加 -yes 或重新运行确认。")
			return
		}
	}

	// 执行卸载
	res, err := runAgent(p.PID, jarPath, "remove", candidates)
	if err != nil {
		rep.addf(SevHigh, removePhase, "remove", "PID "+pidStr+" 卸载 attach 失败", err.Error(),
			"可重试；持续失败请用 Arthas 手工按手册[63]移除。")
		return
	}
	reportRemoval(rep, p, res)
}

func reportScan(rep *Report, p JavaProcess, res *agentResult) {
	pidStr := strconv.Itoa(p.PID)
	if res.Error != "" {
		rep.note("PID %d agent 扫描内部错误: %s", p.PID, res.Error)
	}
	for _, it := range res.Results {
		switch it.Status {
		case "found":
			rep.addf(SevCritical, removePhase, "remove",
				"PID "+pidStr+" 运行时命中内存马: "+it.Class,
				it.RegisteredAs, "建议卸载（下方将请求确认）。")
		case "loaded_not_registered":
			rep.addf(SevHigh, removePhase, "remove",
				"PID "+pidStr+" 加载了内存马类但未在注册表中: "+it.Class,
				it.Detail, "无法热卸载注册项，重启可清除；务必同时排查磁盘注入器与漏洞入口。")
		}
	}
}

func reportRemoval(rep *Report, p JavaProcess, res *agentResult) {
	pidStr := strconv.Itoa(p.PID)
	if res.Error != "" {
		rep.note("PID %d agent 卸载内部错误: %s", p.PID, res.Error)
	}
	if len(res.Results) == 0 {
		rep.addf(SevInfo, removePhase, "remove", "PID "+pidStr+" 卸载未返回结果项", "", "")
		return
	}
	for _, it := range res.Results {
		switch it.Status {
		case "removed":
			rep.addf(SevInfo, removePhase, "remove",
				"✔ PID "+pidStr+" 已热卸载: "+it.Class,
				it.RegisteredAs+"  |  "+it.Detail,
				"内存注册已清除。务必再排查并删除磁盘注入器 JSP/篡改配置，否则重启或再次访问会复活。")
		case "loaded_not_registered":
			rep.addf(SevHigh, removePhase, "remove",
				"PID "+pidStr+" 类已加载但无注册项可卸载: "+it.Class,
				it.Detail, "重启可清除该类；重点查磁盘注入器与入侵入口。")
		case "not_found":
			rep.addf(SevInfo, removePhase, "remove",
				"PID "+pidStr+" 未发现目标类: "+it.Class,
				it.Detail, "该 JVM 未加载此类。")
		case "error":
			rep.addf(SevHigh, removePhase, "remove",
				"✘ PID "+pidStr+" 卸载失败: "+it.Class,
				it.RegisteredAs+"  |  "+it.Detail,
				"用 Arthas 按手册[62][63]手工移除 FilterDef/FilterMap。")
		default:
			rep.addf(SevInfo, removePhase, "remove",
				"PID "+pidStr+" "+it.Class+": "+it.Status, it.Detail, "")
		}
	}
}

// runAgent attach 目标 JVM，加载 agent 执行 scan/remove，读取并解析结果 JSON。
func runAgent(pid int, jarPath, action string, classes []string) (*agentResult, error) {
	resultPath, err := reserveTempName(".memcheck-res-", ".json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(resultPath)

	args := fmt.Sprintf("action=%s;result=%s;classes=%s", action, resultPath, strings.Join(classes, ","))
	code, output, err := attachLoadAgent(pid, jarPath, args)
	if err != nil {
		return nil, err
	}

	// 优先读结果文件；agent 也会把 JSON 打到 attach 输出
	data, rerr := os.ReadFile(resultPath)
	if rerr != nil || len(data) == 0 {
		if j := extractJSON(output); j != "" {
			data = []byte(j)
		} else {
			return nil, fmt.Errorf("attach 返回码 %d，但未获得结果（output: %s）", code, truncate(output, 200))
		}
	}
	var res agentResult
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("解析 agent 结果失败: %w", err)
	}
	return &res, nil
}

// writeAgentJar 把内嵌 agent.jar 释放到 /tmp（world-readable，供目标 uid 读取）。
func writeAgentJar() (string, func(), error) {
	f, err := os.CreateTemp("/tmp", ".memcheck-agent-*.jar")
	if err != nil {
		return "", func() {}, err
	}
	if _, err := f.Write(agentJar); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", func() {}, err
	}
	f.Close()
	// 目标 JVM 以其自身 uid 读取该 jar，需 world-readable
	os.Chmod(f.Name(), 0644)
	path := f.Name()
	return path, func() { os.Remove(path) }, nil
}

// reserveTempName 生成一个唯一临时文件名但不保留文件，交由目标 JVM(agent)以自身 uid 创建。
func reserveTempName(prefix, suffix string) (string, error) {
	f, err := os.CreateTemp("/tmp", prefix+"*"+suffix)
	if err != nil {
		return "", err
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return name, nil
}

func confirmRemoval(p JavaProcess, classes []string) bool {
	if !isTerminal(os.Stdin) {
		fmt.Fprintf(os.Stderr, "%s非交互式环境且未指定 -yes，出于安全默认跳过 PID %d 的卸载。%s\n",
			colYellow, p.PID, colReset)
		return false
	}
	fmt.Fprintf(os.Stderr, "\n%s即将从 PID %d 热卸载以下已确认的恶意内存马类:%s\n", colBold, p.PID, colReset)
	for _, c := range classes {
		desc := ""
		if d, ok := matchKnownMalware(c); ok {
			desc = "  (" + d + ")"
		}
		fmt.Fprintf(os.Stderr, "   %s- %s%s%s\n", colRed, c, colReset, desc)
	}
	fmt.Fprintf(os.Stderr, "%s只在内存中移除注册，不删除磁盘文件、不重启服务。确认卸载？[y/N]: %s", colYellow, colReset)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	ans := strings.TrimSpace(strings.ToLower(line))
	return ans == "y" || ans == "yes"
}

// extractJSON 从 agent 的 attach 输出中提取 JSON（形如 [MemCheckAgent] {...}）。
func extractJSON(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i >= 0 && j > i {
		return s[i : j+1]
	}
	return ""
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
