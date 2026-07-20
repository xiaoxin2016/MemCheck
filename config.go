package main

import (
	"archive/zip"
	"os"
	"regexp"
	"strings"
	"time"
)

// listJarEntries 用标准库 archive/zip 列出 jar 内条目（jar 即 zip）。
func listJarEntries(path string) ([]string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	names := make([]string, 0, len(r.File))
	for _, f := range r.File {
		names = append(names, f.Name)
	}
	return names, nil
}

var (
	reFilterClass   = regexp.MustCompile(`(?is)<filter-class>\s*(.*?)\s*</filter-class>`)
	reListenerClass = regexp.MustCompile(`(?is)<listener-class>\s*(.*?)\s*</listener-class>`)
	reValveClass    = regexp.MustCompile(`(?is)<Valve[^>]*className\s*=\s*"([^"]+)"`)
	reServletClass  = regexp.MustCompile(`(?is)<servlet-class>\s*(.*?)\s*</servlet-class>`)
)

// checkConfigs 对应手册第三阶段 [15]-[19]：检查 web.xml / server.xml / resin.xml 篡改。
func checkConfigs(rep *Report, roots []string, cfg scanConfig) {
	const phase = "阶段三 · 配置文件篡改"
	cutoff := time.Now().AddDate(0, 0, -cfg.recentDays)
	deadline := time.Now().Add(cfg.timeout / 2)

	seen := map[string]bool{}
	for _, root := range roots {
		walk(root, deadline, func(path string, d os.DirEntry) {
			if seen[path] {
				return
			}
			name := strings.ToLower(d.Name())
			switch name {
			case "web.xml":
				seen[path] = true
				inspectWebXML(rep, phase, path, cutoff)
			case "server.xml":
				seen[path] = true
				inspectServerXML(rep, phase, path, cutoff)
			case "resin.xml", "resin-web.xml":
				seen[path] = true
				inspectResinXML(rep, phase, path, cutoff)
			}
		})
	}
}

func inspectWebXML(rep *Report, phase, path string, cutoff time.Time) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)
	fi, _ := os.Stat(path)

	recentNote := ""
	if fi != nil && fi.ModTime().After(cutoff) {
		recentNote = "（配置近期被修改）"
		rep.addf(SevMedium, phase, "config",
			"web.xml 近期被修改"+recentNote,
			evidenceFile(path, fi), "对照备份/版本库确认是否被注入恶意 Filter/Listener。")
	}

	check := func(re *regexp.Regexp, kind string) {
		for _, m := range re.FindAllStringSubmatch(content, -1) {
			cls := strings.TrimSpace(m[1])
			if cls == "" {
				continue
			}
			if desc, ok := matchKnownMalware(cls); ok {
				rep.addf(SevCritical, phase, "config",
					"web.xml 注册了已知内存马 "+kind+": "+desc,
					path+"  ->  "+cls, "备份后删除对应 <"+strings.ToLower(kind)+"> 与 mapping，再重启。")
				continue
			}
			if isWhitelistedFilter(cls) {
				continue
			}
			if reason, susp := looksSuspiciousClassName(cls); susp {
				rep.addf(SevHigh, phase, "config",
					"web.xml 注册了可疑 "+kind+": "+reason,
					path+"  ->  "+cls, "非白名单组件，人工确认；确属恶意则删除注册后重启。")
			} else {
				rep.addf(SevLow, phase, "config",
					"web.xml 中非白名单 "+kind+"（需人工确认）",
					path+"  ->  "+cls, "对照业务确认该组件是否应存在。")
			}
		}
	}
	check(reFilterClass, "Filter")
	check(reListenerClass, "Listener")
	check(reServletClass, "Servlet")
}

func inspectServerXML(rep *Report, phase, path string, cutoff time.Time) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)
	fi, _ := os.Stat(path)
	if fi != nil && fi.ModTime().After(cutoff) {
		rep.addf(SevMedium, phase, "config",
			"server.xml 近期被修改",
			evidenceFile(path, fi), "检查是否被注入恶意 Valve/Realm。")
	}
	for _, m := range reValveClass.FindAllStringSubmatch(content, -1) {
		cls := strings.TrimSpace(m[1])
		if isWhitelistedFilter(cls) || strings.HasPrefix(cls, "org.apache.catalina") {
			continue
		}
		if reason, susp := looksSuspiciousClassName(cls); susp {
			rep.addf(SevHigh, phase, "config",
				"server.xml 中可疑 Valve: "+reason,
				path+"  ->  "+cls, "Valve 型内存马可拦截所有请求，人工确认来源。")
		} else {
			rep.addf(SevLow, phase, "config",
				"server.xml 中非标准 Valve（需人工确认）",
				path+"  ->  "+cls, "确认该 Valve 是否业务需要。")
		}
	}
}

func inspectResinXML(rep *Report, phase, path string, cutoff time.Time) {
	fi, _ := os.Stat(path)
	if fi != nil && fi.ModTime().After(cutoff) {
		rep.addf(SevMedium, phase, "config",
			"Resin 配置("+path+")近期被修改",
			evidenceFile(path, fi), "检查是否有可疑 servlet/filter 映射。")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)
	for _, m := range reServletClass.FindAllStringSubmatch(content, -1) {
		cls := strings.TrimSpace(m[1])
		if isWhitelistedFilter(cls) {
			continue
		}
		if reason, susp := looksSuspiciousClassName(cls); susp {
			rep.addf(SevHigh, phase, "config",
				"resin 配置中可疑 servlet/filter: "+reason,
				path+"  ->  "+cls, "人工确认是否恶意映射。")
		}
	}
}
