package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// scanConfig 磁盘扫描参数
type scanConfig struct {
	roots      []string      // 扫描根目录
	recentDays int           // 近期修改天数阈值
	maxFile    int64         // 读取内容的单文件大小上限（字节）
	full       bool          // 是否从 / 全盘扫描
	deadline   time.Time     // 扫描截止时间（可选）
	timeout    time.Duration // 单次扫描超时
}

// 需要跳过的伪文件系统/无关大目录
var skipDirs = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true, "/run": true,
	"/snap": true, "/var/lib/docker/overlay2": true,
}

var skipDirNames = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true,
}

// resolveRoots 自动定位应用部署路径（对应 [6]）。
func resolveRoots(rep *Report, cfg scanConfig, procs []JavaProcess) []string {
	if cfg.full {
		rep.note("已启用全盘扫描 (--full)，从 / 开始，速度较慢。")
		return []string{"/"}
	}
	set := map[string]bool{}
	// 1) 用户显式指定 —— 显式 --root 时以其为准，不再叠加自动线索，保证扫描范围可控
	if len(cfg.roots) > 0 {
		var roots []string
		for _, r := range cfg.roots {
			if r != "" && dirExists(r) {
				roots = append(roots, filepath.Clean(r))
			} else if r != "" {
				rep.note("指定的 --root 不存在，已忽略: %s", r)
			}
		}
		roots = dedupNested(roots)
		rep.note("磁盘扫描根目录(来自 --root): %s", strings.Join(roots, ", "))
		return roots
	}
	// 2) 从 Java 进程 cwd / -Dcatalina.base / -Dcatalina.home / classpath 提取
	for _, p := range procs {
		if p.Cwd != "" && dirExists(p.Cwd) {
			set[p.Cwd] = true
		}
		for _, arg := range p.Cmdline {
			for _, key := range []string{"-Dcatalina.base=", "-Dcatalina.home=", "-Duser.dir=", "-Dapp.home="} {
				if strings.HasPrefix(arg, key) {
					v := strings.TrimPrefix(arg, key)
					if dirExists(v) {
						set[v] = true
					}
				}
			}
			// Spring Boot fat jar 路径
			if strings.HasSuffix(arg, ".jar") && fileExists(arg) {
				set[filepath.Dir(arg)] = true
			}
		}
	}
	// 3) 常见中间件目录线索
	for _, h := range AppRootHints {
		if dirExists(h) {
			set[h] = true
		}
	}
	var roots []string
	for r := range set {
		roots = append(roots, r)
	}
	if len(roots) == 0 {
		rep.note("未能自动定位应用目录，回退扫描 /opt /usr/local /srv /home /app /data。")
		for _, d := range []string{"/opt", "/usr/local", "/srv", "/home", "/app", "/data"} {
			if dirExists(d) {
				roots = append(roots, d)
			}
		}
	}
	roots = dedupNested(roots)
	rep.note("磁盘扫描根目录: %s", strings.Join(roots, ", "))
	return roots
}

// checkDisk 对应手册第二阶段 [7]-[14]：查找注入器 JSP/class、危险代码、work 编译产物、隐藏文件、fat jar。
func checkDisk(rep *Report, cfg scanConfig, roots []string) {
	const phase = "阶段二 · 磁盘注入器排查"
	cutoff := time.Now().AddDate(0, 0, -cfg.recentDays)
	deadline := time.Now().Add(cfg.timeout)

	scanned := map[string]bool{}
	for _, root := range roots {
		if deadlinePassed(deadline) {
			rep.note("磁盘扫描超时 (%s)，已扫描部分目录，可增大 --timeout 或缩小 --root。", cfg.timeout)
			break
		}
		walk(root, deadline, func(path string, d os.DirEntry) {
			if scanned[path] {
				return
			}
			scanned[path] = true
			name := d.Name()
			lower := strings.ToLower(name)

			switch {
			case strings.HasSuffix(lower, ".jsp") || strings.HasSuffix(lower, ".jspx"):
				inspectJSP(rep, phase, path, cutoff)
			case strings.HasSuffix(lower, ".class"):
				inspectClass(rep, phase, path, cutoff)
			case strings.HasSuffix(lower, ".java") && strings.Contains(path, "/work/") && strings.Contains(path, "Catalina"):
				inspectWorkJava(rep, phase, path, cutoff)
			}

			// 隐藏文件（对应 [13]）: webapps 下以 . 开头的可疑脚本
			if strings.HasPrefix(name, ".") && name != "." && name != ".." &&
				strings.Contains(path, "webapps") &&
				(strings.HasSuffix(lower, ".jsp") || strings.HasSuffix(lower, ".jspx") || strings.HasSuffix(lower, ".class")) {
				rep.addf(SevHigh, phase, "disk",
					"webapps 下的隐藏文件（普通 ls 不可见）",
					path, "攻击者可能命名为 .malicious.jsp 隐藏注入器，人工核查内容。")
			}
		})
	}
}

func inspectJSP(rep *Report, phase, path string, cutoff time.Time) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	recent := fi.ModTime().After(cutoff)

	hits, known := scanFileKeywords(path)
	base := filepath.Base(path)
	randomName := looksRandomFileName(base)

	// 命中已知恶意特征
	if known != "" {
		rep.addf(SevCritical, phase, "disk",
			"JSP 命中已知内存马特征: "+known,
			evidenceFile(path, fi), "极可能是注入器，取证后按手册删除并重启。")
		return
	}
	if len(hits) > 0 {
		sev := SevHigh
		detail := "命中危险关键词: " + strings.Join(hits, ", ")
		if recent {
			sev = SevCritical
			detail += "（且在近期修改窗口内）"
		}
		rep.addf(sev, phase, "disk",
			"JSP 包含类加载/命令执行等危险代码（疑似内存马注入器）",
			evidenceFile(path, fi), "cat 查看内容确认；确属注入器则删除后重启，重启后 Arthas 复核。", detail)
		return
	}
	// 无危险关键词，但近期新增 + 随机文件名 + 非常规目录
	if recent && randomName {
		rep.addf(SevMedium, phase, "disk",
			"近期新增且文件名疑似随机的 JSP",
			evidenceFile(path, fi), "核对是否业务文件；随机名 + 近期新增常为 webshell。")
	}
}

func inspectClass(rep *Report, phase, path string, cutoff time.Time) {
	// 正常类应在 jar 内；WEB-INF/lib、/lib 下的独立 class 相对可信，其余可疑（对应 [11]）
	if strings.Contains(path, "/lib/") {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	base := strings.TrimSuffix(filepath.Base(path), ".class")
	if desc, ok := matchKnownMalware(base); ok {
		rep.addf(SevCritical, phase, "disk",
			"磁盘 class 文件命中已知内存马特征: "+desc,
			evidenceFile(path, fi), "取证后删除并重启。")
		return
	}
	if reason, susp := looksSuspiciousClassName(base); susp {
		rep.addf(SevHigh, phase, "disk",
			"可疑 class 文件类名: "+reason,
			evidenceFile(path, fi), "非 lib 目录下的独立 class 高度可疑，人工反编译确认。")
		return
	}
	if fi.ModTime().After(cutoff) {
		rep.addf(SevMedium, phase, "disk",
			"近期修改的独立 class 文件（非 jar 内）",
			evidenceFile(path, fi), "正常类多在 lib/*.jar 内，独立 class 需确认来源。")
	}
}

func inspectWorkJava(rep *Report, phase, path string, cutoff time.Time) {
	// Tomcat work/Catalina 下 JSP 编译产物（对应 [12]）
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	base := filepath.Base(path)
	if desc, ok := matchKnownMalware(base); ok {
		rep.addf(SevCritical, phase, "disk",
			"Tomcat work 目录 JSP 编译产物命中已知内存马: "+desc,
			evidenceFile(path, fi), "对应的注入器 JSP 一定存在于 webapps，顺藤摸瓜删除源 JSP。")
		return
	}
	if fi.ModTime().After(cutoff) {
		if hits, known := scanFileKeywords(path); known != "" || len(hits) > 0 {
			d := known
			if d == "" {
				d = "危险关键词: " + strings.Join(hits, ", ")
			}
			rep.addf(SevHigh, phase, "disk",
				"Tomcat work 目录近期编译的 JSP 含危险代码",
				evidenceFile(path, fi), "定位对应源 JSP（webapps 下同名）删除。", d)
		}
	}
}

// scanFileKeywords 读取文件内容，返回命中的危险关键词，以及命中的已知恶意特征描述。
func scanFileKeywords(path string) (hits []string, known string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ""
	}
	defer f.Close()
	// 只读前 512KB，避免大文件拖慢
	lr := io.LimitReader(f, 512*1024)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, ""
	}
	content := string(data)

	if desc, ok := matchKnownMalware(content); ok {
		known = desc
	}
	seen := map[string]bool{}
	for _, kw := range SuspiciousInjectorKeywords {
		if strings.Contains(content, kw) && !seen[kw] {
			hits = append(hits, kw)
			seen[kw] = true
		}
	}
	return hits, known
}

// checkSpringBootJars 对应 [14]: 检查近期修改的 fat jar 内是否含非框架 Filter/Servlet。
func checkSpringBootJars(rep *Report, roots []string, cfg scanConfig) {
	const phase = "阶段二 · Spring Boot fat jar"
	cutoff := time.Now().AddDate(0, 0, -cfg.recentDays)
	deadline := time.Now().Add(cfg.timeout / 2)
	seen := map[string]bool{}
	for _, root := range roots {
		walk(root, deadline, func(path string, d os.DirEntry) {
			if seen[path] || !strings.HasSuffix(strings.ToLower(d.Name()), ".jar") {
				return
			}
			seen[path] = true
			fi, err := os.Stat(path)
			if err != nil || !fi.ModTime().After(cutoff) {
				return
			}
			names, err := listJarEntries(path)
			if err != nil {
				return
			}
			var suspicious []string
			for _, n := range names {
				if !strings.HasSuffix(n, ".class") {
					continue
				}
				cls := strings.TrimSuffix(strings.ReplaceAll(n, "/", "."), ".class")
				if d2, ok := matchKnownMalware(cls); ok {
					rep.addf(SevCritical, phase, "disk",
						"fat jar 内含已知内存马类: "+d2,
						path+" -> "+n, "jar 被篡改植入内存马，替换为可信构建产物。")
					return
				}
				if reason, susp := looksSuspiciousClassName(cls); susp {
					suspicious = append(suspicious, cls+" ("+reason+")")
				}
			}
			if len(suspicious) > 0 {
				rep.addf(SevHigh, phase, "disk",
					"近期修改的 fat jar 内含疑似非框架 Filter/Servlet",
					evidenceFile(path, fi),
					"确认是否业务组件；非预期即为植入。", strings.Join(suspicious, "\n"))
			}
		})
	}
}

// ---- 工具函数 ----

func evidenceFile(path string, fi os.FileInfo) string {
	return path + "  size=" + strconv.FormatInt(fi.Size(), 10) +
		"  mtime=" + fi.ModTime().Format("2006-01-02 15:04:05")
}

// looksRandomFileName 判断文件名主体是否像随机串（如 aB3xK.jsp）。
func looksRandomFileName(name string) bool {
	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if len(stem) < 4 || len(stem) > 24 {
		return false
	}
	var upper, lower, digit int
	for _, r := range stem {
		switch {
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= 'a' && r <= 'z':
			lower++
		case r >= '0' && r <= '9':
			digit++
		default:
			return false // 含分隔符，多为业务命名
		}
	}
	// 大小写混合 + 含数字，且不含常见业务词 -> 疑似随机
	mixedCase := upper > 0 && lower > 0
	if mixedCase && digit > 0 {
		low := strings.ToLower(stem)
		for _, w := range []string{"index", "login", "main", "test", "error", "list", "view", "edit", "config"} {
			if strings.Contains(low, w) {
				return false
			}
		}
		return true
	}
	return false
}

func walk(root string, deadline time.Time, fn func(path string, d os.DirEntry)) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return io.EOF // 用 EOF 作为提前终止信号
		}
		if d.IsDir() {
			if skipDirs[path] || skipDirNames[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		fn(path, d)
		return nil
	})
}

func deadlinePassed(t time.Time) bool { return !t.IsZero() && time.Now().After(t) }

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// dedupNested 去除被其他根目录包含的子目录，避免重复扫描。
func dedupNested(roots []string) []string {
	var out []string
	for _, r := range roots {
		nested := false
		for _, other := range roots {
			if r != other && strings.HasPrefix(r+"/", other+"/") {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, r)
		}
	}
	// 去重
	seen := map[string]bool{}
	var res []string
	for _, r := range out {
		if !seen[r] {
			seen[r] = true
			res = append(res, r)
		}
	}
	return res
}

// readLines 读取文件前若干行（供日志/配置检查复用）。
func readLines(path string, max int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if max > 0 && len(lines) >= max {
			break
		}
	}
	return lines, sc.Err()
}
