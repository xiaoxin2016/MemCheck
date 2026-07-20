//go:build !linux

package main

import "fmt"

// 非 Linux 平台不支持 HotSpot attach 卸载（内存马排查/卸载均面向 Linux 生产环境）。

const attachSupported = false

func attachLoadAgent(pid int, jarPath, agentArgs string) (int, string, error) {
	return -1, "", fmt.Errorf("当前平台不支持 JVM attach 卸载（仅 Linux）")
}

func checkAttachable(pid int) error {
	return fmt.Errorf("当前平台不支持 JVM attach 卸载（仅 Linux）")
}
