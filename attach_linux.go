//go:build linux

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// attachLoadAgent 通过 HotSpot attach 机制把 java agent 加载进目标 JVM（纯 Go 实现，无 cgo）。
// 返回 JVM 侧解析该 attach 操作的返回码、agent 输出，以及错误。
//
// 参考 jattach 的 Linux 实现：创建 .attach_pid<nspid> 文件 -> 向目标发送 SIGQUIT ->
// 目标在 /tmp 建立 Unix socket .java_pid<nspid> -> 连接并按协议发送 load 命令。
func attachLoadAgent(pid int, jarPath, agentArgs string) (int, string, error) {
	if err := checkAttachable(pid); err != nil {
		return -1, "", err
	}
	ns := nsPID(pid)
	uid, gid := procOwner(pid)
	sockPath := filepath.Join("/tmp", fmt.Sprintf(".java_pid%d", ns))

	if !fileExists(sockPath) {
		attachName := fmt.Sprintf(".attach_pid%d", ns)
		candidates := []string{
			filepath.Join(fmt.Sprintf("/proc/%d/cwd", pid), attachName),
			filepath.Join("/tmp", attachName),
		}
		var made string
		for _, c := range candidates {
			f, err := os.OpenFile(c, os.O_CREATE|os.O_WRONLY, 0660)
			if err == nil {
				f.Close()
				_ = os.Chown(c, uid, gid) // 需与目标进程同 uid，root 下 chown
				made = c
				break
			}
		}
		if made == "" {
			return -1, "", fmt.Errorf("无法创建 attach 触发文件（权限不足？建议以 root 运行）")
		}
		defer os.Remove(made)

		// 重试发送 SIGQUIT，等待 socket 出现
		ok := false
		for attempt := 0; attempt < 6 && !ok; attempt++ {
			if err := syscall.Kill(pid, syscall.SIGQUIT); err != nil {
				return -1, "", fmt.Errorf("向 PID %d 发送 SIGQUIT 失败: %w", pid, err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if fileExists(sockPath) {
					ok = true
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
		if !ok {
			return -1, "", fmt.Errorf("等待 attach socket %s 超时（目标可能非 HotSpot JVM 或处于其它命名空间）", sockPath)
		}
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return -1, "", fmt.Errorf("连接 attach socket 失败: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 协议: "1\0" + command + 3 个参数（NUL 结尾，不足补空）
	// 加载 java agent: load instrument false <jar>=<args>
	var req strings.Builder
	req.WriteString("1\x00")
	req.WriteString("load\x00")
	req.WriteString("instrument\x00")
	req.WriteString("false\x00")
	req.WriteString(jarPath + "=" + agentArgs + "\x00")
	if _, err := conn.Write([]byte(req.String())); err != nil {
		return -1, "", fmt.Errorf("发送 attach 命令失败: %w", err)
	}

	data, err := io.ReadAll(conn)
	if err != nil && len(data) == 0 {
		return -1, "", fmt.Errorf("读取 attach 响应失败: %w", err)
	}
	// 首行为返回码
	resp := string(data)
	code := -1
	rest := resp
	if i := strings.IndexByte(resp, '\n'); i >= 0 {
		if c, err := strconv.Atoi(strings.TrimSpace(resp[:i])); err == nil {
			code = c
		}
		rest = resp[i+1:]
	}
	return code, strings.TrimSpace(rest), nil
}

// checkAttachable 检查目标是否可 attach（同一 PID/mount 命名空间，即非容器隔离）。
func checkAttachable(pid int) error {
	if nsPID(pid) != pid {
		return fmt.Errorf("目标 PID %d 运行在独立 PID 命名空间（容器）中，请在该容器内运行 memcheck", pid)
	}
	self, err1 := os.Readlink("/proc/self/ns/mnt")
	target, err2 := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err1 == nil && err2 == nil && self != target {
		return fmt.Errorf("目标 PID %d 处于不同的挂载命名空间（容器），请在该容器内运行 memcheck", pid)
	}
	return nil
}

// nsPID 读取目标在其 PID 命名空间内的 pid（NSpid 最后一段）。
func nsPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return pid
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if n, err := strconv.Atoi(f[len(f)-1]); err == nil {
					return n
				}
			}
		}
	}
	return pid
}

// procOwner 返回目标进程的 uid/gid。
func procOwner(pid int) (int, int) {
	var st syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/proc/%d", pid), &st); err == nil {
		return int(st.Uid), int(st.Gid)
	}
	return os.Getuid(), os.Getgid()
}

// attachSupported 标识当前平台支持 attach。
const attachSupported = true
