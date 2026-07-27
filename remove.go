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

const removePhase = "阶段九 · 运行时内存马排查(attach)"

// removeOptions 运行时排查/卸载参数
type removeOptions struct {
	enabled   bool
	scanOnly  bool     // -attach-scan: 只 attach 枚举报告运行时过滤器链，不做任何卸载
	classes   []string // -remove-class 显式指定的目标类（覆盖自动推荐）
	assumeYes bool     // -yes 跳过交互确认
}

// agentResult / agentItem 与 MemCheckAgent 回写的 JSON 对应
type agentResult struct {
	ContextsFound int         `json:"contextsFound"`
	Action        string      `json:"action"`
	Error         string      `json:"error"`
	Inventory     []invItem   `json:"inventory"` // action=list 返回的已注册组件清单
	Results       []agentItem `json:"results"`   // action=remove 返回的处置结果
}

// invItem 一条已注册组件（Filter/Servlet/Listener）
type invItem struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Class      string `json:"class"`
	CodeSource string `json:"codeSource"` // 类的 codeSource 位置；内存注入通常为空
	Loader     string `json:"loader"`     // 加载该类的 classloader 类型
	Resolved   bool   `json:"resolved"`   // 是否成功解析到 Class（拿到 codeSource）
}

type agentItem struct {
	Class        string `json:"class"`
	Status       string `json:"status"`
	RegisteredAs string `json:"registeredAs"`
	Detail       string `json:"detail"`
}

// classifyComponent 用 Go 侧统一启发式判定一条已注册组件的风险，返回等级与原因。
// 关键信号是 codeSource：内存注入(反序列化/defineClass)的类通常 codeSource 为空，
// 而正常应用/框架的组件 codeSource 指向其 jar——这样即使内存马类名/包名完全正常也能被发现，
// 且不会误伤有正常 codeSource 的业务过滤器。对应手册对 codeSource 的研判逻辑。
func classifyComponent(it invItem) (sev Severity, reason string, candidate bool) {
	// 已知内存马特征（类名或注册名命中）→ 最高优先
	if d, ok := matchKnownMalware(it.Class); ok {
		return SevCritical, "命中已知内存马特征: " + d, true
	}
	if it.Name != "" {
		if d, ok := matchKnownMalware(it.Name); ok {
			return SevCritical, "注册名命中已知内存马特征: " + d, true
		}
	}
	// 框架/JDK 内部 → 正常，跳过
	if isTrustedClassName(it.Class) || isWhitelistedFilter(it.Class) {
		return SevInfo, "", false
	}
	// codeSource 为空 + 已成功解析到类 → 极可能是内存注入（defineClass 无 ProtectionDomain）
	if it.Resolved && it.CodeSource == "" {
		return SevCritical, "codeSource 为空，疑似内存注入(反序列化/defineClass)", true
	}
	// codeSource 指向 JSP → JSP 注入器编译加载
	if strings.Contains(strings.ToLower(it.CodeSource), ".jsp") {
		return SevCritical, "codeSource 指向 JSP，疑似 JSP 注入器加载", true
	}
	// 类名启发式（无包名 / 生僻词+组件后缀 / 包名异常）
	if r, susp := looksSuspiciousClassName(it.Class); susp {
		return SevHigh, r, true
	}
	// Lambda 伪装
	if strings.Contains(it.Class, "$$Lambda$") && !isTrustedClassName(it.Class) {
		return SevHigh, "Lambda 表达式伪装的 " + it.Kind, true
	}
	// 类无法解析（可能已被隐藏）→ 提示但不自动卸载
	if !it.Resolved {
		return SevLow, "无法解析该类(可能已卸载/隐藏)", false
	}
	return SevInfo, "", false
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

	// 卸载会改动运行中的应用，进入前给出一次明确提示（枚举为只读，无需额外提示）
	if !opt.scanOnly {
		fmt.Fprintf(os.Stderr, "%s[memcheck]%s 卸载模式：仅在内存移除注册，不改磁盘/不重启\n", colYellow, colReset)
	}

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
	if len(opt.classes) > 0 && !opt.scanOnly {
		// 手工指定：直接作为候选，跳过枚举
		candidates = opt.classes
	} else {
		// 枚举全部已注册组件，用 Go 侧启发式挑出可疑项（不依赖硬编码类名）
		res, err := runAgent(p.PID, jarPath, "list", nil)
		if err != nil {
			rep.addf(SevMedium, removePhase, "remove", "PID "+pidStr+" 运行时枚举失败", err.Error(),
				"确认目标为 HotSpot JVM 且权限足够。")
			return
		}
		candidates = reportInventory(rep, p, res)
	}

	// 只读枚举模式：报告后即返回，不做任何卸载
	if opt.scanOnly {
		if len(candidates) > 0 {
			rep.addf(SevInfo, removePhase, "remove",
				"PID "+pidStr+" 运行时发现 "+strconv.Itoa(len(candidates))+" 个可疑组件（只读枚举，未卸载）",
				strings.Join(candidates, ", "),
				"确认后可用 -remove（自动）或 -remove-class <类名>（定向）热卸载。")
		}
		return
	}

	if len(candidates) == 0 {
		return // reportInventory 已给出说明
	}

	// 交互确认（-yes 跳过）
	if !opt.assumeYes {
		if !confirmRemoval(p, candidates) {
			rep.note("PID %d 用户取消卸载。", p.PID)
			rep.addf(SevInfo, removePhase, "remove", "PID "+pidStr+" 已跳过卸载（用户取消/非交互）",
				strings.Join(candidates, ", "), "如需卸载请加 -yes，或重新运行确认。")
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

// reportInventory 报告枚举到的组件清单，标记可疑项，返回推荐卸载的类名列表。
func reportInventory(rep *Report, p JavaProcess, res *agentResult) []string {
	pidStr := strconv.Itoa(p.PID)
	if res.Error != "" {
		rep.note("PID %d agent 枚举内部错误: %s", p.PID, res.Error)
	}
	if res.ContextsFound == 0 {
		rep.addf(SevMedium, removePhase, "remove",
			"PID "+pidStr+" attach 成功但未发现 Tomcat 上下文",
			"", "可能是非 Tomcat 容器(Resin/Jetty/Undertow)或 context 尚未启动；改用 Arthas 复核。")
		return nil
	}

	var candidates []string
	seen := map[string]bool{}
	suspicious := 0
	filters, servlets, listeners := 0, 0, 0
	for _, it := range res.Inventory {
		switch it.Kind {
		case "filter":
			filters++
		case "servlet":
			servlets++
		case "listener":
			listeners++
		}
		sev, reason, cand := classifyComponent(it)
		if cand {
			suspicious++
			where := it.Kind
			if it.Name != "" {
				where += ":" + it.Name
			}
			rep.addf(sev, removePhase, "remove",
				"PID "+pidStr+" 运行时发现可疑"+it.Kind+": "+it.Class,
				where+" -> "+it.Class+"  ("+reason+")",
				"疑似内存马，下方将请求确认后热卸载。")
			if it.Class != "" && !seen[it.Class] {
				seen[it.Class] = true
				candidates = append(candidates, it.Class)
			}
		}
	}

	// 概览 + 完整 filter 类名清单（等价 Arthas sc -d *Filter*，便于人工核对/手工 -remove-class）
	rep.addf(SevInfo, removePhase, "remove",
		fmt.Sprintf("PID %s 运行时组件枚举: 上下文 %d，Filter %d/Servlet %d/Listener %d，可疑 %d",
			pidStr, res.ContextsFound, filters, servlets, listeners, suspicious),
		inventoryList(res.Inventory),
		"若确有内存马但未被自动判定，可用 -remove-class <类名> 手工指定卸载。")

	return candidates
}

func inventoryList(inv []invItem) string {
	var b strings.Builder
	for _, it := range inv {
		name := it.Name
		if name == "" {
			name = "-"
		}
		cs := it.CodeSource
		if cs == "" {
			cs = "codeSource=空"
		}
		fmt.Fprintf(&b, "\n  [%s] %s : %s  (%s)", it.Kind, name, it.Class, cs)
	}
	s := b.String()
	if len(s) > 4000 {
		s = s[:4000] + "\n  …(清单过长已截断)"
	}
	return strings.TrimPrefix(s, "\n")
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
