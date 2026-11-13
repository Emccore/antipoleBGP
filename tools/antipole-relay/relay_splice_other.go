//go:build !linux

// 非 Linux 构建目标：splice 不可用，转发始终走 read/write 循环。
package main

import "syscall"

const spliceSupported = false

type rawConnConn interface {
	SyscallConn() (syscall.RawConn, error)
}

// splicePump 非 Linux 无实现：调用方由 spliceSupported 守卫，此路径不可达
func splicePump(src, dst rawConnConn) (int64, error) {
	return 0, syscall.ENOTSUP
}
