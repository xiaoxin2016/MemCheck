package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// Severity 风险等级
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func (s Severity) label() string {
	switch s {
	case SevCritical:
		return "严重"
	case SevHigh:
		return "高危"
	case SevMedium:
		return "中危"
	case SevLow:
		return "低危"
	default:
		return "信息"
	}
}

func (s Severity) color() string {
	switch s {
	case SevCritical:
		return colRedBold
	case SevHigh:
		return colRed
	case SevMedium:
		return colYellow
	case SevLow:
		return colCyan
	default:
		return colGray
	}
}

// Finding 一条排查发现
type Finding struct {
	Severity Severity `json:"severity"`
	SevName  string   `json:"severity_name"`
	Phase    string   `json:"phase"`    // 排查阶段
	Category string   `json:"category"` // 分类
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Evidence string   `json:"evidence,omitempty"` // 文件路径/行/命令等
	Advice   string   `json:"advice,omitempty"`   // 处置建议
}

// Report 汇总
type Report struct {
	mu        sync.Mutex
	Host      string    `json:"host"`
	StartedAt string    `json:"started_at"`
	Findings  []Finding `json:"findings"`
	Notes     []string  `json:"notes"` // 执行过程说明（跳过/降级等）
}

func (r *Report) add(f Finding) {
	f.SevName = f.Severity.String()
	r.mu.Lock()
	r.Findings = append(r.Findings, f)
	r.mu.Unlock()
}

// addf 便捷方法
func (r *Report) addf(sev Severity, phase, category, title, evidence, advice string, detailArgs ...interface{}) {
	detail := ""
	if len(detailArgs) > 0 {
		if fs, ok := detailArgs[0].(string); ok {
			detail = fmt.Sprintf(fs, detailArgs[1:]...)
		}
	}
	r.add(Finding{
		Severity: sev, Phase: phase, Category: category,
		Title: title, Detail: detail, Evidence: evidence, Advice: advice,
	})
}

func (r *Report) note(format string, args ...interface{}) {
	r.mu.Lock()
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
	r.mu.Unlock()
}

// counts 按等级统计
func (r *Report) counts() map[Severity]int {
	m := map[Severity]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

// sortFindings 按严重程度降序、阶段升序稳定排序
func (r *Report) sortFindings() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].Severity != r.Findings[j].Severity {
			return r.Findings[i].Severity > r.Findings[j].Severity
		}
		return r.Findings[i].Phase < r.Findings[j].Phase
	})
}

// ---- 终端着色 ----

var (
	colReset   = "\033[0m"
	colRed     = "\033[31m"
	colRedBold = "\033[1;31m"
	colGreen   = "\033[32m"
	colYellow  = "\033[33m"
	colCyan    = "\033[36m"
	colGray    = "\033[90m"
	colBold    = "\033[1m"
)

func disableColor() {
	colReset, colRed, colRedBold, colGreen, colYellow, colCyan, colGray, colBold =
		"", "", "", "", "", "", "", ""
}

// printText 输出人类可读报告
func (r *Report) printText(w *os.File) {
	r.sortFindings()
	c := r.counts()

	fmt.Fprintf(w, "%s%s╔══════════════════════════════════════════════════════════════════════╗%s\n", colBold, colCyan, colReset)
	fmt.Fprintf(w, "%s%s║   内存马应急排查自动化报告  (MemCheck)  —  只读检测，不做任何删除     ║%s\n", colBold, colCyan, colReset)
	fmt.Fprintf(w, "%s%s╚══════════════════════════════════════════════════════════════════════╝%s\n", colBold, colCyan, colReset)
	fmt.Fprintf(w, "主机: %s   开始时间: %s\n", r.Host, r.StartedAt)
	fmt.Fprintf(w, "统计: %s严重 %d%s  %s高危 %d%s  %s中危 %d%s  %s低危 %d%s  %s信息 %d%s\n\n",
		colRedBold, c[SevCritical], colReset,
		colRed, c[SevHigh], colReset,
		colYellow, c[SevMedium], colReset,
		colCyan, c[SevLow], colReset,
		colGray, c[SevInfo], colReset)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "%s未发现明显异常。仍建议结合 Arthas / 日志进行人工复核。%s\n", colGreen, colReset)
	}

	lastPhase := ""
	for i, f := range r.Findings {
		if f.Phase != lastPhase {
			fmt.Fprintf(w, "\n%s%s── %s ──%s\n", colBold, colGreen, f.Phase, colReset)
			lastPhase = f.Phase
		}
		fmt.Fprintf(w, "%s[%s]%s %s%s%s\n", f.Severity.color(), f.Severity.label(), colReset, colBold, f.Title, colReset)
		if f.Detail != "" {
			for _, line := range strings.Split(f.Detail, "\n") {
				fmt.Fprintf(w, "      %s\n", line)
			}
		}
		if f.Evidence != "" {
			fmt.Fprintf(w, "      %s证据:%s %s\n", colGray, colReset, f.Evidence)
		}
		if f.Advice != "" {
			fmt.Fprintf(w, "      %s建议:%s %s\n", colCyan, colReset, f.Advice)
		}
		if i == len(r.Findings)-1 {
			fmt.Fprintln(w)
		}
	}

	if len(r.Notes) > 0 {
		fmt.Fprintf(w, "%s执行说明:%s\n", colGray, colReset)
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  %s- %s%s\n", colGray, n, colReset)
		}
		fmt.Fprintln(w)
	}

	printJudgeGuide(w)
}

// printJSON 输出机器可读报告
func (r *Report) printJSON(w *os.File) error {
	r.sortFindings()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// printJudgeGuide 输出研判指南（来源: 手册「六、排查结果判断指南」）
func printJudgeGuide(w *os.File) {
	guide := `研判指南（对照手册 codeSource 判断）:
  • 发现可疑 JSP / class 注入器  → 该文件即注入器，先删文件再重启，重启后用 Arthas 复核。
  • web.xml 中有可疑 Filter/Listener → 备份后删除恶意注册，再重启。
  • JVM 启动参数含 -javaagent(非APM) → Agent 型，删 agent jar + 清启动脚本参数后重启。
  • 磁盘无任何可疑文件            → 可能远程漏洞一次性注入，重启即清除，但务必查日志定位入口。
  • Arthas 中 codeSource 指向 JSP → 磁盘有注入器；codeSource 为空 → 漏洞直接注入。

下一步（本工具不自动执行清除）:
  1) 用 Arthas: sc -d <可疑类名> | grep -i "classloader\|codeSource" 定位加载来源。
  2) 确认后按手册「四、内存马清除操作」人工处置：先删注入器 → 清配置 → 重启 → 复核。`
	fmt.Fprintf(w, "%s%s%s\n", colCyan, guide, colReset)
}
