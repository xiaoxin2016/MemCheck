package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// checkLogs 对应手册第七阶段 [44]-[48]：日志定位入侵时间/注入请求。
func checkLogs(rep *Report, roots []string, cfg scanConfig) {
	const phase = "阶段七 · 日志分析"
	deadline := time.Now().Add(cfg.timeout / 2)

	var logFiles []string
	seen := map[string]bool{}
	for _, root := range roots {
		walk(root, deadline, func(path string, dnt os.DirEntry) {
			if seen[path] {
				return
			}
			name := strings.ToLower(dnt.Name())
			if strings.HasPrefix(name, "localhost_access_log") ||
				strings.HasPrefix(name, "access_log") ||
				name == "catalina.out" {
				seen[path] = true
				logFiles = append(logFiles, path)
			}
		})
	}
	if len(logFiles) == 0 {
		rep.addf(SevInfo, phase, "log", "未发现常见 Tomcat 访问/运行日志",
			"", "确认日志目录（可能被清理），或检查 Nginx/接入层日志。")
		return
	}

	for _, lf := range logFiles {
		fi, err := os.Stat(lf)
		if err != nil {
			continue
		}
		base := strings.ToLower(filepath.Base(lf))
		if base == "catalina.out" {
			scanCatalinaOut(rep, phase, lf, fi)
		} else {
			scanAccessLog(rep, phase, lf, fi)
		}
	}
}

func scanAccessLog(rep *Report, phase, path string, fi os.FileInfo) {
	lines, err := readLastLines(path, 5000)
	if err != nil {
		return
	}
	var suspiciousPOST, wsUpgrade int
	var samplePOST, sampleWS string
	for _, line := range lines {
		low := strings.ToLower(line)
		if strings.Contains(line, "POST") && !containsAny(low, ".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".svg") {
			suspiciousPOST++
			if samplePOST == "" {
				samplePOST = strings.TrimSpace(line)
			}
		}
		if strings.Contains(low, "upgrade") || strings.Contains(low, "websocket") {
			wsUpgrade++
			if sampleWS == "" {
				sampleWS = strings.TrimSpace(line)
			}
		}
	}
	if wsUpgrade > 0 {
		rep.addf(SevMedium, phase, "log",
			"访问日志中存在 WebSocket 升级请求（哥斯拉 PlasmodesmaFilter 走 WebSocket）",
			path+" (共 "+itoa(wsUpgrade)+" 条)  例: "+truncate(sampleWS, 200),
			"结合 sc -d *PlasmodesmaFilter* 确认是否哥斯拉内存马。")
	}
	if suspiciousPOST > 0 {
		rep.addf(SevInfo, phase, "log",
			"访问日志中非静态资源 POST 请求 "+itoa(suspiciousPOST)+" 条（可能含注入请求）",
			path+"  例: "+truncate(samplePOST, 200),
			"重点看参数为 Base64、路径可疑的 POST，定位注入时间点与入口。")
	}
	rep.addf(SevInfo, phase, "log",
		"访问日志: "+filepath.Base(path)+"  最后修改 "+fi.ModTime().Format("2006-01-02 15:04:05"),
		path, "日志修改时间有助于界定入侵时间窗口。")
}

func scanCatalinaOut(rep *Report, phase, path string, fi os.FileInfo) {
	lines, err := readLastLines(path, 3000)
	if err != nil {
		return
	}
	var hits []string
	for _, line := range lines {
		for _, kw := range []string{"defineClass", "ClassLoader", "Base64", "ProcessBuilder", "Runtime.getRuntime"} {
			if strings.Contains(line, kw) {
				hits = append(hits, truncate(strings.TrimSpace(line), 160))
				break
			}
		}
		if len(hits) >= 8 {
			break
		}
	}
	if len(hits) > 0 {
		rep.addf(SevMedium, phase, "log",
			"catalina.out 出现类加载/命令执行相关异常（可能是注入时报错）",
			path, "以下为样本行，可据此定位注入时间与手法:\n"+strings.Join(hits, "\n"))
	}
}

// readLastLines 读取文件末尾 n 行（避免整读大日志）。
func readLastLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const chunk = 64 * 1024
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	var buf []byte
	var pos = size
	lineCount := 0
	for pos > 0 && lineCount <= n {
		readSize := int64(chunk)
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		tmp := make([]byte, readSize)
		if _, err := f.ReadAt(tmp, pos); err != nil {
			break
		}
		buf = append(tmp, buf...)
		lineCount = strings.Count(string(buf), "\n")
	}
	all := strings.Split(string(buf), "\n")
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func itoa(n int) string { return strconv.Itoa(n) }
