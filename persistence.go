package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// checkPersistence 对应手册第八/九阶段 [49]-[58]：定时任务、启动项、启动脚本、SSH 密钥、SUID。
func checkPersistence(rep *Report, roots []string, cfg scanConfig) {
	checkCron(rep)
	checkStartupFiles(rep)
	checkStartupScripts(rep, roots, cfg)
	checkAuthorizedKeys(rep)
	checkSUID(rep)
}

const phasePersist = "阶段八 · 持久化与启动项"

func firstMatch(s string, keywords []string) (string, bool) {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return kw, true
		}
	}
	return "", false
}

// 定时任务中的强特征：反弹 shell / Agent / 临时目录执行（命中即高危）
var cronStrongKeywords = []string{
	"/dev/tcp/", "bash -i", "sh -i", "mkfifo", "-javaagent", "-agentpath",
	"/dev/shm/", "base64 -d", "base64 --decode", "nc -e", "ncat -e",
	"socat ", "python -c", "perl -e",
}

// 定时任务中的弱特征：下载/临时目录（命中提示人工确认，中危，降低误报）
var cronSoftKeywords = []string{
	"curl ", "wget ", "/tmp/",
}

func checkCron(rep *Report) {
	files := []string{"/etc/crontab"}
	// /etc/cron.d/*, /etc/cron.{hourly,daily,...}, 用户 crontab
	for _, dir := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					files = append(files, filepath.Join(dir, e.Name()))
				}
			}
		}
	}
	// 用户 crontab（spool）
	for _, spool := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		if entries, err := os.ReadDir(spool); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					files = append(files, filepath.Join(spool, e.Name()))
				}
			}
		}
	}
	for _, f := range files {
		lines, err := readLines(f, 2000)
		if err != nil {
			continue
		}
		for _, line := range lines {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			low := strings.ToLower(t)
			if kw, hit := firstMatch(low, cronStrongKeywords); hit {
				rep.addf(SevHigh, phasePersist, "cron",
					"定时任务含反弹shell/Agent等强特征 ("+kw+")",
					f+":  "+truncate(t, 200),
					"高度可疑，恶意 cron 常用于重复注入/回连，人工确认后清除。")
				continue
			}
			if kw, hit := firstMatch(low, cronSoftKeywords); hit {
				rep.addf(SevMedium, phasePersist, "cron",
					"定时任务含下载/临时目录执行特征 ("+strings.TrimSpace(kw)+")",
					f+":  "+truncate(t, 200),
					"确认该 cron 是否业务需要（部分为系统正常任务）。")
			}
		}
	}
}

func checkStartupFiles(rep *Report) {
	for _, f := range []string{"/etc/rc.local"} {
		lines, err := readLines(f, 500)
		if err != nil {
			continue
		}
		for _, line := range lines {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") || t == "exit 0" {
				continue
			}
			low := strings.ToLower(t)
			if containsAny(low, "curl", "wget", "/tmp/", "-javaagent", "base64", "/dev/shm/", "nc ", "/dev/tcp/") {
				rep.addf(SevHigh, phasePersist, "startup",
					"rc.local 含可疑启动命令",
					f+":  "+truncate(t, 200), "启动项常用于持久化，人工确认。")
			}
		}
	}
	// systemd: 扫描 unit 文件中可疑 ExecStart
	for _, dir := range []string{"/etc/systemd/system", "/run/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			lines, err := readLines(p, 300)
			if err != nil {
				continue
			}
			for _, line := range lines {
				low := strings.ToLower(line)
				if strings.HasPrefix(strings.TrimSpace(low), "execstart") &&
					containsAny(low, "/tmp/", "/dev/shm/", "-javaagent", "base64 -d", "curl", "wget", "/dev/tcp/") {
					rep.addf(SevHigh, phasePersist, "startup",
						"systemd 服务含可疑 ExecStart",
						p+":  "+truncate(strings.TrimSpace(line), 200),
						"确认该服务来源；恶意服务可实现开机持久化。")
				}
			}
		}
	}
}

// checkStartupScripts 对应 [55]: setenv.sh / catalina.sh 是否被注入 -javaagent。
func checkStartupScripts(rep *Report, roots []string, cfg scanConfig) {
	deadline := time.Now().Add(cfg.timeout / 3)
	seen := map[string]bool{}
	for _, root := range roots {
		walk(root, deadline, func(path string, dnt os.DirEntry) {
			if seen[path] {
				return
			}
			name := dnt.Name()
			if name != "setenv.sh" && name != "catalina.sh" && name != "startup.sh" {
				return
			}
			seen[path] = true
			lines, err := readLines(path, 1000)
			if err != nil {
				return
			}
			for _, line := range lines {
				if strings.Contains(line, "-javaagent") || strings.Contains(line, "-agentpath") {
					rep.addf(SevHigh, phasePersist, "startup",
						"启动脚本中包含 -javaagent/-agentpath 参数",
						path+":  "+truncate(strings.TrimSpace(line), 200),
						"确认该 agent 是否 APM/诊断工具；非预期即为 Agent 型内存马持久化，删除该参数与 jar。")
				}
			}
		})
	}
}

func checkAuthorizedKeys(rep *Report) {
	// 常见位置: /root/.ssh, /home/*/.ssh
	var dirs []string
	dirs = append(dirs, "/root/.ssh")
	if homes, err := os.ReadDir("/home"); err == nil {
		for _, h := range homes {
			if h.IsDir() {
				dirs = append(dirs, filepath.Join("/home", h.Name(), ".ssh"))
			}
		}
	}
	for _, dir := range dirs {
		p := filepath.Join(dir, "authorized_keys")
		lines, err := readLines(p, 200)
		if err != nil {
			continue
		}
		fi, _ := os.Stat(p)
		count := 0
		for _, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), "ssh-") || strings.Contains(l, "ssh-rsa") || strings.Contains(l, "ssh-ed25519") {
				count++
			}
		}
		if count > 0 {
			mt := ""
			if fi != nil {
				mt = "  mtime=" + fi.ModTime().Format("2006-01-02 15:04:05")
			}
			rep.addf(SevMedium, phasePersist, "ssh",
				"发现 authorized_keys（含 "+itoa(count)+" 个公钥）",
				p+mt, "核对是否全部为运维已知公钥，攻击者常添加自己的公钥做持久化后门。")
		}
	}
}

func checkSUID(rep *Report) {
	// 对应 [58]: 非标准目录下的 SUID 文件
	stdPrefixes := []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/"}
	roots := []string{"/tmp", "/dev/shm", "/var/tmp", "/home", "/opt", "/srv", "/data"}
	deadline := time.Now().Add(15 * time.Second)
	for _, root := range roots {
		if !dirExists(root) {
			continue
		}
		walk(root, deadline, func(path string, dnt os.DirEntry) {
			info, err := dnt.Info()
			if err != nil {
				return
			}
			mode := info.Mode()
			if mode&os.ModeSetuid == 0 {
				return
			}
			for _, pre := range stdPrefixes {
				if strings.HasPrefix(path, pre) {
					return
				}
			}
			rep.addf(SevHigh, phasePersist, "suid",
				"非标准目录下的 SUID 文件（可能用于提权）",
				path+"  mode="+mode.String()+"  mtime="+info.ModTime().Format("2006-01-02 15:04:05"),
				"确认来源，攻击者常留 SUID 后门提权。")
		})
	}
}
