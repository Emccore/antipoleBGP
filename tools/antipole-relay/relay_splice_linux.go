//go:build linux

// 内核态零拷贝搬运：splice 把数据从源 socket 直接送进目标 socket，
// 全程不经过用户态（节省 2 次内存拷贝）。V3.6 曾尝试 splice 但未达预期，
// 原因是未做攒批——每次 splice 仅获取约 3KB，系统调用次数反而显著增加。
// 本版做法：
//   - 只在「有积压」时切入（上次 read 满 256KB 才算有积压），平时仍走
//     read/write 循环，交互流量零影响；
//   - 每方向持有一条 1MB 大管道（池化复用），填满再排空，每 MB 只有
//     2 次 splice 系统调用；
//   - EAGAIN 交给 netpoller 等待（RawConn.Read/Write 回调返回 false），
//     不空转、不阻塞 OS 线程。
package main

import (
	"io"
	"sync"
	"syscall"
)

// rawConnConn 能拿到原始 fd 的连接（*net.TCPConn 与 peekedConn 均实现）
type rawConnConn interface {
	SyscallConn() (syscall.RawConn, error)
}

// spliceSupported：当前构建是否具备 splice 能力（linux 编译目标为 true）
const spliceSupported = true

const (
	fcntlSetPipeSz = 1031 // F_SETPIPE_SZ（syscall 包未定义常量）
	spliceMove     = 0x1  // SPLICE_F_MOVE
	spliceNonblock = 0x2  // SPLICE_F_NONBLOCK
)

// splicePipe 一条可复用的内核管道（非阻塞，容量尽量扩到 1MB）
type splicePipe struct {
	r, w int
}

var splicePipePool = sync.Pool{New: func() any {
	var fds [2]int
	if err := syscall.Pipe2(fds[:], syscall.O_NONBLOCK|syscall.O_CLOEXEC); err != nil {
		return nil // 分配失败：Get 得到 nil，调用方回退 read/write
	}
	p := &splicePipe{r: fds[0], w: fds[1]}
	// 扩容失败不影响正确性：默认 64KB 容量仍可工作，仅系统调用次数增多
	_, _, _ = syscall.Syscall(syscall.SYS_FCNTL,
		uintptr(p.w), fcntlSetPipeSz, pipeCap)
	return p
}}

func getSplicePipe() *splicePipe {
	if p, _ := splicePipePool.Get().(*splicePipe); p != nil {
		return p
	}
	return nil
}

func putSplicePipe(p *splicePipe) {
	if p != nil {
		splicePipePool.Put(p)
	}
}

// splicePump 尽力搬一轮：把 src 填进管道（填满或源暂时取空），再排空到 dst。
// 返回搬运字节数与错误；EOF 以 io.EOF 语义返回，与 read 循环一致。
// 限速不走此路径（调用方保证 limiter.rate<=0）。
//
// 死锁要点：填循环遇到 EAGAIN 必须**立即返回执行排空**，绝不能挂载 poller 等待
// 源数据——否则"管道没填满→不排空→不读源→源侧窗口满不发→永远填不满"
// 形成互等死锁。排空阶段挂载 poller 等待可写是安全的（dst 可写仅依赖对端消费）。
func splicePump(src, dst rawConnConn) (int64, error) {
	sp := getSplicePipe()
	if sp == nil {
		return 0, syscall.ENOTSUP
	}
	// 任何退出路径都要保证管道被排空后才归还：脏管道会给下一个复用者
	// 混入上一个连接的数据（表现为传输尾部多出/错乱几十字节）
	defer func() {
		drainSplicePipe(sp)
		putSplicePipe(sp)
	}()

	sraw, err := src.SyscallConn()
	if err != nil {
		return 0, err
	}
	draw, err := dst.SyscallConn()
	if err != nil {
		return 0, err
	}

	var total int64
	eof := false
	for !eof {
		// 填：socket→pipe。首次循环（管道空）允许挂载 poller 等待可读——此刻
		// socket 缓冲已搬空、接收窗口打开，上游可发，不存在互等；
		// 非首次循环（管道有数据）EAGAIN 必须立即返回排空，否则管道被占用
		// 不放会把接收窗口耗成 0，与上游互等死锁。
		filled := 0
		first := true
		for filled < pipeCap {
			var n int64
			var serr error
			if err := sraw.Read(func(sfd uintptr) bool {
				n, serr = syscall.Splice(int(sfd), nil, sp.w, nil,
					pipeCap-filled, spliceMove|spliceNonblock)
				if serr == syscall.EAGAIN {
					return !first // 管道空才允许挂载等待；有数据立即转排空
				}
				return true
			}); err != nil {
				return total, err
			}
			first = false
			if serr != nil && serr != syscall.EAGAIN {
				return total, serr
			}
			if n == 0 && serr == nil {
				eof = true // 对端写方向关闭（splice 返回 0 = EOF）
				break
			}
			filled += int(n)
			if serr == syscall.EAGAIN {
				break // 源暂时取空：先排空已搬运数据
			}
		}

		// 排空：pipe→dst。挂载 poller 等待可写是安全的（dst 可写仅依赖对端消费）。
		drained := 0
		for drained < filled {
			var n int64
			var werr error
			if err := draw.Write(func(dfd uintptr) bool {
				n, werr = syscall.Splice(sp.r, nil, int(dfd), nil,
					filled-drained, spliceMove|spliceNonblock)
				if werr == syscall.EAGAIN {
					return false
				}
				return true
			}); err != nil {
				return total, err
			}
			if werr != nil && werr != syscall.EAGAIN {
				return total, werr
			}
			drained += int(n)
		}
		total += int64(drained)
		if eof {
			return total, io.EOF
		}
	}
	return total, nil
}

// drainSplicePipe 丢弃管道内残留数据（非阻塞读到 EAGAIN 为止）
func drainSplicePipe(sp *splicePipe) {
	if sp == nil {
		return
	}
	var scratch [64 << 10]byte
	for {
		n, err := syscall.Read(sp.r, scratch[:])
		if n <= 0 || err != nil {
			return
		}
	}
}
