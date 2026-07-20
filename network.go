package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// tcpConn 一条 TCP 连接
type tcpConn struct {
	localIP    net.IP
	localPort  int
	remoteIP   net.IP
	remotePort int
	state      string
	inode      string
	pid        int
	proc       string
}

// TCP 状态码 -> 名称
var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// checkNetwork 对应手册第四阶段 [20]-[23]：网络连接排查（纯 Go 解析 /proc/net，不依赖 netstat/ss）。
func checkNetwork(rep *Report, javaPIDs map[int]bool) {
	const phase = "阶段四 · 网络连接排查"
	conns := readProcNetTCP(rep)
	if conns == nil {
		return
	}
	inodePID, inodeProc := buildInodePIDMap()

	var established, listening int
	for i := range conns {
		c := &conns[i]
		if pid, ok := inodePID[c.inode]; ok {
			c.pid = pid
			c.proc = inodeProc[pid]
		}
		isJava := javaPIDs[c.pid] || strings.Contains(strings.ToLower(c.proc), "java")

		switch c.state {
		case "ESTABLISHED":
			established++
			if CommonBusinessPorts[c.remotePort] || CommonBusinessPorts[c.localPort] {
				continue // 常见业务端口跳过
			}
			sev := SevLow
			advice := "排除业务端口后的外联连接需逐一确认；到内网其他主机的非业务端口可能是代理隧道(如 Prepupa)。"
			detail := ""
			if isJava {
				sev = SevMedium
				detail = "该连接归属 Java 进程"
				if isPrivate(c.remoteIP) {
					sev = SevHigh
					detail += "，且目标为内网地址——符合代理隧道马特征"
				}
			}
			rep.addf(sev, phase, "network",
				"可疑 ESTABLISHED 外联连接",
				connEvidence(c), advice, detail)
		case "LISTEN":
			listening++
			if CommonBusinessPorts[c.localPort] {
				continue
			}
			// 监听在非业务端口、且非本地回环限定
			if isJava {
				rep.addf(SevMedium, phase, "network",
					"Java 进程监听非业务端口（可能反向 shell / SOCKS 代理）",
					connEvidence(c), "确认该监听端口用途；未知端口结合 Arthas 线程排查。")
			}
		}
	}
	rep.addf(SevInfo, phase, "network",
		fmt.Sprintf("网络连接概览: ESTABLISHED %d 条, LISTEN %d 个", established, listening),
		"", "详见上方可疑项；完整连接可用 ss -antp 复核。")
}

func connEvidence(c *tcpConn) string {
	owner := "未知进程"
	if c.pid > 0 {
		owner = fmt.Sprintf("pid=%d(%s)", c.pid, c.proc)
	}
	return fmt.Sprintf("%s -> %s  [%s]  %s",
		net.JoinHostPort(c.localIP.String(), strconv.Itoa(c.localPort)),
		net.JoinHostPort(c.remoteIP.String(), strconv.Itoa(c.remotePort)),
		c.state, owner)
}

func readProcNetTCP(rep *Report) []tcpConn {
	var all []tcpConn
	found := false
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		lines, err := readLines(f, 0)
		if err != nil {
			continue
		}
		found = true
		for i, line := range lines {
			if i == 0 {
				continue // 表头
			}
			c, ok := parseTCPLine(line)
			if ok {
				all = append(all, c)
			}
		}
	}
	if !found {
		rep.note("无法读取 /proc/net/tcp（非 Linux 或权限不足），网络排查跳过。")
		return nil
	}
	return all
}

func parseTCPLine(line string) (tcpConn, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return tcpConn{}, false
	}
	lip, lport, ok1 := parseHexAddr(fields[1])
	rip, rport, ok2 := parseHexAddr(fields[2])
	if !ok1 || !ok2 {
		return tcpConn{}, false
	}
	state := tcpStates[strings.ToUpper(fields[3])]
	if state == "" {
		state = fields[3]
	}
	return tcpConn{
		localIP: lip, localPort: lport,
		remoteIP: rip, remotePort: rport,
		state: state, inode: fields[9],
	}, true
}

// parseHexAddr 解析 /proc/net/tcp 中的 "0100007F:1F90" 形式地址（小端 hex）。
func parseHexAddr(s string) (net.IP, int, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, 0, false
	}
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return nil, 0, false
	}
	hexIP := parts[0]
	switch len(hexIP) {
	case 8: // IPv4
		b, err := hexToBytes(hexIP)
		if err != nil {
			return nil, 0, false
		}
		ip := net.IPv4(b[3], b[2], b[1], b[0]) // 小端
		return ip, int(port), true
	case 32: // IPv6
		b, err := hexToBytes(hexIP)
		if err != nil {
			return nil, 0, false
		}
		ip := make(net.IP, 16)
		// 每 4 字节一组，组内小端
		for i := 0; i < 4; i++ {
			word := b[i*4 : i*4+4]
			le := binary.LittleEndian.Uint32(word)
			binary.BigEndian.PutUint32(ip[i*4:i*4+4], le)
		}
		return ip, int(port), true
	}
	return nil, 0, false
}

func hexToBytes(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

// buildInodePIDMap 扫描 /proc/*/fd，建立 socket inode -> pid 映射。
func buildInodePIDMap() (map[string]int, map[int]string) {
	inodePID := map[string]int{}
	pidProc := map[int]string{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return inodePID, pidProc
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		name := procComm(pid)
		for _, fd := range fds {
			target := readLink(filepath.Join(fdDir, fd.Name()))
			// 形如 socket:[12345]
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				inode := target[len("socket:[") : len(target)-1]
				inodePID[inode] = pid
				pidProc[pid] = name
			}
		}
	}
	return inodePID, pidProc
}

func procComm(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func isPrivate(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
