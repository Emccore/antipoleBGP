// antipole-relay —— 端口转发「数据面中继」
//
// 反向隧道（类 Cloudflare Tunnel）的数据面：
//   - Python 主进程保留控制面（鉴权、映射决策、防火墙、计费）；
//   - 本进程只负责把「公网连接」与「用户客户端回连的连接」对接并搬运字节。
//
// 与 Python 通过 unix socket 用换行分隔的 JSON 双向通信：
//
//	Go -> Python：ev=conn / ev=done / ev=err
//	Python -> Go：cmd=listen / unlisten / update / kill，以及 accept / reject
//
// 仅使用标准库，无第三方依赖。
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// 控制面连接重试间隔
	controlRetryInterval = 2 * time.Second
	// 等待 Python accept/reject 与客户端带 nonce 回连的超时：高延迟/丢包链路上
	// 回连握手会慢很多，这里放宽以免正常连接被误判超时（只影响失败连接的收尾时长）
	acceptTimeout = 20 * time.Second
	// 等待客户端带 nonce 回连的超时
	nonceTimeout = 20 * time.Second
	// 客户端回连首行读取超时与最大长度
	relayTokenTimeout = 15 * time.Second
	relayTokenMaxLen  = 128
	// 收发缓冲区大小与攒批期限：期限越长单次读写越大、CPU 越低，代价是多几
	// 毫秒的流水线延迟（对吞吐无影响，只作用于持续大流量）。
	// 实测（单 vCPU 小机器）每次循环除读写外还要付十几个调度/轮询系统调用，
	// 单次调用约数十微秒，因此把块攒大比零拷贝更划算：基准 4ms，检测到吞吐
	// 型流量（大块）时自动放大到 4 倍，小块交互流量立即回落到基准。
	// 缓冲区策略：空闲/交互连接每方向只常驻 4KB；检测到持续积压（连续两次读满）
	// 才从池里借 256KB 大缓冲，块回落即归还——数万并发连接时内存不随连接数
	// 线性膨胀，吞吐型流量仍可获得大块。
	copyBufIdle           = 4 << 10
	copyBufMax            = 256 << 10
	coalesceBurstFloor    = 4 << 10  // 小于此值视为交互型流量
	coalesceBurstCeiling  = 16 << 10 // 大于此值视为吞吐型流量
	coalesceMaxMultiplier = 4
	// splice 零拷贝的管道容量：填满再排空，每 MB 只有 2 次 splice 调用
	pipeCap = 1 << 20
)

// bulkBufPool 吞吐态大缓冲池：借出/归还只在突发起落时发生。
var bulkBufPool = sync.Pool{New: func() any {
	buf := make([]byte, copyBufMax)
	return &buf
}}

// bulkPause 攒批基准期限，可由 -bulk-pause-ms 覆盖（0 = 不攒批）。
var bulkPause = 4 * time.Millisecond

// spliceEnable splice 零拷贝开关（-splice）。默认关闭：实测 5MB/s 级 WAN
// 瓶颈链路上 splice 反而 20ms/MB（排空速率受限，1MB 管道填不满，模式碎片化
// + poller 挂起/唤醒次数显著增加）；read+自适应攒批在同链路 5.0 ms/MB 最优。
// 回环/内网等高吞吐场景可开 -splice=true（数据不过用户态）。
var spliceEnable = false

// ---------------------------------------------------------------- IPC 报文

// eventConn：公网连接到达，询问 Python 是否放行。
type eventConn struct {
	Ev   string `json:"ev"`
	UID  uint64 `json:"uid"`
	Port int    `json:"port"`
	ID   uint64 `json:"id"`
}

// eventDone：一条管道结束，附带双向字节数。
type eventDone struct {
	Ev   string `json:"ev"`
	UID  uint64 `json:"uid"`
	ID   uint64 `json:"id"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

// eventErr：出错事件。
type eventErr struct {
	Ev  string `json:"ev"`
	ID  uint64 `json:"id"`
	Why string `json:"why"`
}

// reply：对 Python 命令的应答。
type reply struct {
	OK  bool    `json:"ok"`
	ID  *uint64 `json:"id,omitempty"`
	Err string  `json:"err,omitempty"`
}

// command：Python 下发的消息（命令与 accept/reject 共用同一结构）。
type command struct {
	Cmd   string  `json:"cmd"`
	UID   uint64  `json:"uid"`
	Port  int     `json:"port"`
	Bind  string  `json:"bind"`
	Rate  int64   `json:"rate"`
	ID    *uint64 `json:"id"`
	Nonce string  `json:"nonce"`
	Why   string  `json:"why"`
}

// ---------------------------------------------------------------- 限速

// rateLimiter：简单令牌桶，rate 为字节/秒，<=0 表示不限速。
type rateLimiter struct {
	rate   int64
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newRateLimiter(rate int64) *rateLimiter {
	return &rateLimiter{rate: rate, last: time.Now()}
}

// wait 在令牌不足时阻塞相应时长，使读取 n 字节的速率不超过 rate。
func (limiter *rateLimiter) wait(n int) {
	if limiter.rate <= 0 {
		return
	}
	need := float64(n)
	limiter.mu.Lock()
	now := time.Now()
	limiter.tokens += now.Sub(limiter.last).Seconds() * float64(limiter.rate)
	limiter.last = now
	// 最多积攒 1 秒的令牌作为突发额度
	if limiter.tokens > float64(limiter.rate) {
		limiter.tokens = float64(limiter.rate)
	}
	if limiter.tokens >= need {
		limiter.tokens -= need
		limiter.mu.Unlock()
		return
	}
	deficit := need - limiter.tokens
	limiter.tokens = 0
	limiter.mu.Unlock()

	time.Sleep(time.Duration(deficit / float64(limiter.rate) * float64(time.Second)))
}

// ---------------------------------------------------------------- 埋点统计

// dirStats 单方向的块大小直方图（桶上界 4K/16K/64K/256K）。
// 仅 -stat-file 启用时挂载（copyDirection 收到 nil 即零开销）。
type dirStats struct {
	blocks [5]uint64
	bytes  uint64
}

var statBucketMax = [...]int{4 << 10, 16 << 10, 64 << 10, 256 << 10}

func (st *dirStats) note(n int) {
	idx := 0
	for idx < len(statBucketMax) && n > statBucketMax[idx] {
		idx++
	}
	atomic.AddUint64(&st.blocks[idx], 1)
	atomic.AddUint64(&st.bytes, uint64(n))
}

// statReporter 每 5s 把两个方向的增量分布写入文件；窗口内无活动则不输出。
// 文件超过 4MB 滚动一次（保留一份 .1），长期开启也不会无限增长。
type statReporter struct {
	file                       *os.File
	path                       string
	up, down                   *dirStats
	pipes                      *int64
	prevUp                     [5]uint64
	prevDown                   [5]uint64
	prevUpBytes, prevDownBytes uint64
}

const statRotateBytes = 4 << 20

func (rep *statReporter) rotateIfNeeded() {
	info, err := rep.file.Stat()
	if err != nil || info.Size() < statRotateBytes {
		return
	}
	rep.file.Close()
	os.Rename(rep.path, rep.path+".1")
	file, err := os.OpenFile(rep.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		rep.file = nil
		return
	}
	rep.file = file
}

func statDelta(cur, prev *[5]uint64) (delta [5]uint64, blocks uint64) {
	for i := range cur {
		delta[i] = cur[i] - prev[i]
		blocks += delta[i]
	}
	return
}

func (rep *statReporter) tick() {
	if rep.file == nil {
		return
	}
	rep.rotateIfNeeded()
	if rep.file == nil {
		return
	}
	var curUp, curDown [5]uint64
	for i := range curUp {
		curUp[i] = atomic.LoadUint64(&rep.up.blocks[i])
		curDown[i] = atomic.LoadUint64(&rep.down.blocks[i])
	}
	if curUp == rep.prevUp && curDown == rep.prevDown {
		return
	}
	dUp, nUp := statDelta(&curUp, &rep.prevUp)
	dDown, nDown := statDelta(&curDown, &rep.prevDown)
	rep.prevUp, rep.prevDown = curUp, curDown

	upBytes := atomic.LoadUint64(&rep.up.bytes)
	downBytes := atomic.LoadUint64(&rep.down.bytes)
	// b0..b4 对应 ≤4K/≤16K/≤64K/≤256K/>256K；bytes 为该窗口增量
	fmt.Fprintf(rep.file,
		"%s stat up n=%d bytes=%d b0=%d b1=%d b2=%d b3=%d b4=%d"+
			" | down n=%d bytes=%d b0=%d b1=%d b2=%d b3=%d b4=%d | pipes=%d\n",
		time.Now().Format("2006-01-02 15:04:05.000"),
		nUp, upBytes-rep.prevUpBytes,
		dUp[0], dUp[1], dUp[2], dUp[3], dUp[4],
		nDown, downBytes-rep.prevDownBytes,
		dDown[0], dDown[1], dDown[2], dDown[3], dDown[4],
		atomic.LoadInt64(rep.pipes))
	rep.prevUpBytes, rep.prevDownBytes = upBytes, downBytes
}

func (rep *statReporter) run() {
	for {
		time.Sleep(5 * time.Second)
		rep.tick()
	}
}

// ---------------------------------------------------------------- 字节搬运

// copyDirection 单方向搬运：按“攒批”方式读取，避免一有数据就立刻读出来。
//
// 内核只在数据到达时才唤醒读端，若每次都马上读走，单次读往往只有几 KB，
// 每 KB 都要付出 read+write+事件唤醒的固定代价（实测 3.4KB/次时约 30us/KB）。
// 这里给读设置一个短期限（配合 io.ReadFull），让内核把数据攒成大块再交付，
// 空闲时则去掉期限阻塞等待，不空转。
func copyDirection(dst io.Writer, src net.Conn, counter *int64, limiter *rateLimiter, st *dirStats) error {
	idle := make([]byte, copyBufIdle)
	buf := idle
	var bulk *[]byte
	releaseBulk := func() {
		if bulk != nil {
			bulkBufPool.Put(bulk)
			bulk, buf = nil, idle
		}
	}
	defer releaseBulk()

	burst := false
	backlog := false
	fullReads := 0
	pause := bulkPause
	// splice 前置判定（一次性）：开关 + 能力可用 + 不限速 + 双端都能拿原始 fd
	var spliceSrc, spliceDst rawConnConn
	useSplice := spliceEnable && spliceSupported && limiter.rate <= 0
	if useSplice {
		s, sok := src.(rawConnConn)
		d, dok := dst.(rawConnConn)
		if sok && dok {
			spliceSrc, spliceDst = s, d
		} else {
			useSplice = false
		}
	}
	for {
		// 积压态优先走内核 splice 零拷贝：数据不过用户态，每 MB 只有 2 次
		// splice 系统调用（1MB 管道填满再排空）。不限速 + 双端可取 fd 才启用；
		// 未填满说明积压消失，回 read 模式攒批，交互流量零影响。
		if useSplice && backlog {
			filled, err := splicePump(spliceSrc, spliceDst)
			if filled > 0 {
				if st != nil {
					st.note(int(filled))
				}
				atomic.AddInt64(counter, filled)
			}
			// EOF/错误都直接返回：EOF 已保证管道数据先排空再上报
			if err != nil {
				return err
			}
			// 填满说明仍有积压，继续零拷贝；未填满则积压耗尽，
			// 回 read 模式攒批等新数据，交互流量零影响
			backlog = filled == pipeCap
			if backlog {
				continue
			}
		}
		// 还有积压（上轮把最大缓冲读满）时不再停读：既避免大带宽时延链路被
		// 停读卡出吞吐上限，也少一轮人为等待；块回落自然恢复攒批省 CPU。
		if burst && pause > 0 && !backlog {
			// 突发期：先等一小会儿让内核把数据攒成大块，再一次性读走。
			// 相比「每读一次设一次读期限」，这里没有任何 timer 操作，代价只是
			// 持续大流量时多几毫秒流水线延迟（对吞吐无影响）。
			time.Sleep(pause)
		}
		n, err := src.Read(buf)
		if n > 0 {
			readCap := len(buf) // 本次实际读入的是哪块缓冲，下面全按它判断
			burst = true
			// 自适应攒批：持续大块说明是吞吐型流量，继续放大停读时间以换取
			// 更少的循环与系统调用；一旦回到小块则立刻恢复基准，交互不受累。
			switch {
			case n >= coalesceBurstCeiling:
				if pause < bulkPause*coalesceMaxMultiplier {
					pause *= 2
				}
			case n < coalesceBurstFloor:
				pause = bulkPause
			}
			if limiter.rate > 0 {
				limiter.wait(n)
			}
			if st != nil {
				st.note(n)
			}
			// 必须先把本次读到的数据写完，再换档：换档会把 buf 指向别处、
			// 甚至把大缓冲归还池子（可能立即被别的连接取走复用），
			// 若提前换档，buf[:n] 会越界或写到被复用的内存上。
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			atomic.AddInt64(counter, int64(n))
			backlog = readCap == copyBufMax && n == readCap
			// 自适应缓冲：连续读满说明还有积压，借大缓冲升档；块明显变小即归还
			if n == readCap {
				if fullReads++; fullReads >= 2 && readCap < copyBufMax {
					if bulk == nil {
						bulk = bulkBufPool.Get().(*[]byte)
					}
					buf, fullReads = *bulk, 0
				}
			} else {
				fullReads = 0
				if readCap > copyBufIdle && n < readCap/4 {
					releaseBulk()
				}
			}
		}
		if err != nil {
			return err
		}
		if n == 0 {
			burst = false
			backlog = false
			releaseBulk()
		}
	}
}

// closeWrite 只关闭写方向（半关，发出 FIN），让对端读到 EOF 而另一方向
// 仍可继续收数据；连接不支持半关时退化为整体关闭。
func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	conn.Close()
}

// tuneTCP 针对转发连接做内核层调优：
//   - KeepAlive：高延迟链路经 NAT/中间设备静默回收映射表项时，两端都不会收到
//     通知，保活探测能让内核尽早发现半开连接并收敛；
//   - NoDelay：关掉 Nagle，避免小包被攒住等 ACK（转发路径上每个包都该尽快出手）；
//   - 收发缓冲交给内核自适应（sysctl tcp_rmem/tcp_wmem），不在此显式设定——
//     显式设 SO_RCVBUF 会关掉该 socket 的自动调优，空闲连接反而失去"按需长大"。
func tuneTCP(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	// 15s：家用 NAT/运营商防火墙的 TCP 表项普遍 30~60s 回收，探测必须更密；
	// 空闲数据通道被静默回收是"连接看着在、数据却不动"的直接原因
	tcp.SetKeepAlive(true)
	tcp.SetKeepAlivePeriod(15 * time.Second)
	tcp.SetNoDelay(true)
}

// ---------------------------------------------------------------- 连接对象

// peekedConn 允许把「探测断开时多读到的一个字节」回灌给数据流，避免丢包或乱序。
type peekedConn struct {
	net.Conn
	mu     sync.Mutex
	prefix []byte
}

func (conn *peekedConn) Read(p []byte) (int, error) {
	conn.mu.Lock()
	if len(conn.prefix) > 0 {
		n := copy(p, conn.prefix)
		conn.prefix = conn.prefix[n:]
		conn.mu.Unlock()
		return n, nil
	}
	conn.mu.Unlock()
	return conn.Conn.Read(p)
}

func (conn *peekedConn) pushPrefix(b byte) {
	conn.mu.Lock()
	conn.prefix = append(conn.prefix, b)
	conn.mu.Unlock()
}

// CloseWrite 把半关闭透传到内层连接。net.Conn 接口本身不含 CloseWrite，
// 嵌入后方法不会被提升；不显式转发的话公网侧半关会退化成整体 close，
// 照样把对向在途数据 RST 掉。
func (conn *peekedConn) CloseWrite() error {
	if cw, ok := conn.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return conn.Conn.Close()
}

// SyscallConn 透传原始 fd（splice 零拷贝路径需要）。同为嵌入接口不提升，
// 需显式转发。
func (conn *peekedConn) SyscallConn() (syscall.RawConn, error) {
	if rc, ok := conn.Conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		return rc.SyscallConn()
	}
	return nil, syscall.ENOTSUP
}

// pipe 表示一条正在搬运的隧道。
type pipe struct {
	id     uint64
	uid    uint64
	pub    net.Conn // 公网侧（已包装为 peekedConn）
	client net.Conn // 客户端回连侧
	up     int64    // 公网 -> 客户端 字节数
	down   int64    // 客户端 -> 公网 字节数
}

// publicConn 表示一条尚未完成对接的公网连接。
type publicConn struct {
	id    uint64
	uid   uint64
	port  int
	conn  *peekedConn
	relay *Relay

	mu       sync.Mutex
	nonce    string
	accepted bool
	finished bool
	client   net.Conn

	acceptCh     chan struct{} // accept 到达后关闭
	rejectCh     chan string   // reject 原因
	clientReady  chan struct{} // 客户端回连成功且已挂载后关闭
	disconnectCh chan struct{} // 公网连接在对接完成前断开

	stopping       atomic.Bool
	monitorDone    chan struct{}
	monitorOnce    sync.Once
	disconnectOnce sync.Once
}

func (pub *publicConn) signalDisconnect() {
	pub.disconnectOnce.Do(func() { close(pub.disconnectCh) })
}

// startMonitor 探测公网连接是否在对接完成前断开；顺带把读到的首字节回灌。
func (pub *publicConn) startMonitor() {
	go func() {
		defer close(pub.monitorDone)
		one := make([]byte, 1)
		n, err := pub.conn.Read(one)
		if n > 0 {
			pub.conn.pushPrefix(one[0])
			return
		}
		// 被 stopMonitor 主动打断时不算断开
		if err != nil && !pub.stopping.Load() {
			pub.signalDisconnect()
		}
	}()
}

// stopMonitor 结束探测协程，并清除读超时，之后连接可专供搬运使用。
func (pub *publicConn) stopMonitor() {
	pub.monitorOnce.Do(func() {
		pub.stopping.Store(true)
		pub.conn.SetReadDeadline(time.Now())
		<-pub.monitorDone
		pub.conn.SetReadDeadline(time.Time{})
	})
}

// ---------------------------------------------------------------- 监听项

type listenerEntry struct {
	uid  uint64
	port int
	ln   net.Listener
}

func listenerKey(uid uint64, port int) string {
	return strconv.FormatUint(uid, 10) + ":" + strconv.Itoa(port)
}

// listenOn 按地址族显式指定网络：IPv4 用 tcp4，避免 Go 把 "0.0.0.0" 当双栈
// 通配（[::]）去绑，从而与已绑定的具体 IPv6 地址互相冲突（EADDRINUSE）。
func listenOn(address string) (net.Listener, error) {
	network := "tcp6"
	if host, _, err := net.SplitHostPort(address); err == nil && !strings.Contains(host, ":") {
		network = "tcp4"
	}
	return net.Listen(network, address)
}

// ---------------------------------------------------------------- 中继主体

// Relay 保存全部运行时状态。
type Relay struct {
	control *controlClient

	relayListeners []net.Listener

	mu        sync.Mutex
	listeners map[string]*listenerEntry

	userMu    sync.RWMutex
	userRates map[uint64]int64

	pipeMu     sync.Mutex
	pipesByUID map[uint64]map[*pipe]struct{}

	regMu   sync.Mutex
	byNonce map[string]*publicConn
	byID    map[uint64]*publicConn

	idCounter uint64

	// 埋点：statUp 为公网->客户端方向，statDown 为客户端->公网方向；
	// 仅在 -stat-file 启用时非 nil。
	statUp   *dirStats
	statDown *dirStats
	pipes    int64
}

func newRelay() *Relay {
	return &Relay{
		listeners:  make(map[string]*listenerEntry),
		userRates:  make(map[uint64]int64),
		pipesByUID: make(map[uint64]map[*pipe]struct{}),
		byNonce:    make(map[string]*publicConn),
		byID:       make(map[uint64]*publicConn),
	}
}

func (relay *Relay) sendEvent(v any) {
	if relay.control != nil {
		relay.control.send(v)
	}
}

func (relay *Relay) reply(id *uint64, ok bool, errMsg string) {
	if relay.control != nil {
		relay.control.reply(id, ok, errMsg)
	}
}

func (relay *Relay) userRate(uid uint64) int64 {
	relay.userMu.RLock()
	defer relay.userMu.RUnlock()
	return relay.userRates[uid]
}

// ---------------------------------------------------------------- 控制面命令

func (relay *Relay) cmdListen(cmd command) {
	key := listenerKey(cmd.UID, cmd.Port)

	relay.mu.Lock()
	if _, ok := relay.listeners[key]; ok {
		relay.mu.Unlock()
		relay.reply(cmd.ID, true, "")
		return
	}
	relay.mu.Unlock()

	address := net.JoinHostPort(cmd.Bind, strconv.Itoa(cmd.Port))
	listener, err := listenOn(address)
	if err != nil {
		log.Printf("监听失败 uid=%d port=%d addr=%s: %v", cmd.UID, cmd.Port, address, err)
		relay.reply(cmd.ID, false, err.Error())
		return
	}

	entry := &listenerEntry{uid: cmd.UID, port: cmd.Port, ln: listener}

	relay.mu.Lock()
	if _, ok := relay.listeners[key]; ok {
		relay.mu.Unlock()
		listener.Close()
		relay.reply(cmd.ID, true, "")
		return
	}
	relay.listeners[key] = entry
	relay.mu.Unlock()

	go relay.acceptPublicLoop(entry)
	log.Printf("开始监听 uid=%d port=%d addr=%s", cmd.UID, cmd.Port, address)
	relay.reply(cmd.ID, true, "")
}

func (relay *Relay) cmdUnlisten(cmd command) {
	key := listenerKey(cmd.UID, cmd.Port)

	relay.mu.Lock()
	entry, ok := relay.listeners[key]
	if ok {
		delete(relay.listeners, key)
	}
	relay.mu.Unlock()

	if ok {
		entry.ln.Close()
		log.Printf("停止监听 uid=%d port=%d", cmd.UID, cmd.Port)
	}
	relay.reply(cmd.ID, true, "")
}

func (relay *Relay) cmdUpdate(cmd command) {
	relay.userMu.Lock()
	relay.userRates[cmd.UID] = cmd.Rate
	relay.userMu.Unlock()
	relay.reply(cmd.ID, true, "")
}

func (relay *Relay) cmdKill(cmd command) {
	relay.pipeMu.Lock()
	var targets []*pipe
	for p := range relay.pipesByUID[cmd.UID] {
		targets = append(targets, p)
	}
	relay.pipeMu.Unlock()

	for _, p := range targets {
		p.pub.Close()
		p.client.Close()
	}
	relay.reply(cmd.ID, true, "")
}

func (relay *Relay) cmdAccept(id uint64, nonce string) {
	relay.regMu.Lock()
	pub, ok := relay.byID[id]
	relay.regMu.Unlock()
	if !ok {
		return
	}

	pub.mu.Lock()
	if pub.finished || pub.accepted {
		pub.mu.Unlock()
		return
	}
	pub.accepted = true
	pub.nonce = nonce
	pub.mu.Unlock()

	relay.regMu.Lock()
	relay.byNonce[nonce] = pub
	relay.regMu.Unlock()

	close(pub.acceptCh)
}

func (relay *Relay) cmdReject(id uint64, why string) {
	relay.regMu.Lock()
	pub, ok := relay.byID[id]
	relay.regMu.Unlock()
	if !ok {
		return
	}

	pub.mu.Lock()
	if pub.accepted || pub.finished {
		pub.mu.Unlock()
		return
	}
	pub.finished = true
	pub.mu.Unlock()

	pub.rejectCh <- why
}

// ---------------------------------------------------------------- 公网侧监听

func (relay *Relay) acceptPublicLoop(entry *listenerEntry) {
	for {
		conn, err := entry.ln.Accept()
		if err != nil {
			return // 监听被关闭
		}
		tuneTCP(conn)
		id := atomic.AddUint64(&relay.idCounter, 1)
		pub := &publicConn{
			id:           id,
			uid:          entry.uid,
			port:         entry.port,
			conn:         &peekedConn{Conn: conn},
			relay:        relay,
			acceptCh:     make(chan struct{}),
			rejectCh:     make(chan string, 1),
			clientReady:  make(chan struct{}),
			disconnectCh: make(chan struct{}),
			monitorDone:  make(chan struct{}),
		}

		relay.regMu.Lock()
		relay.byID[id] = pub
		relay.regMu.Unlock()

		go relay.servePublic(pub)
	}
}

// servePublic 询问 Python 并等待客户端回连，成功后开始搬运。
func (relay *Relay) servePublic(pub *publicConn) {
	defer relay.removeByID(pub.id)

	relay.sendEvent(eventConn{Ev: "conn", UID: pub.uid, Port: pub.port, ID: pub.id})
	pub.startMonitor()

	timer := time.NewTimer(acceptTimeout)
	defer timer.Stop()

	select {
	case <-pub.acceptCh:
		// 已获准，等待客户端带 nonce 回连
		select {
		case <-pub.clientReady:
			pub.stopMonitor()
			relay.startBridge(pub, pub.client)
		case <-pub.disconnectCh:
			pub.stopMonitor()
			relay.unregisterNonce(pub)
			pub.conn.Close()
			relay.sendEvent(eventErr{Ev: "err", ID: pub.id, Why: "客户端回连前公网连接已断开"})
		case <-timer.C:
			// 处理「超时」与「刚好回连成功」同时发生的情况
			pub.mu.Lock()
			client := pub.client
			pub.finished = true
			pub.mu.Unlock()
			if client != nil {
				pub.stopMonitor()
				relay.startBridge(pub, client)
				return
			}
			pub.stopMonitor()
			relay.unregisterNonce(pub)
			pub.conn.Close()
			relay.sendEvent(eventErr{Ev: "err", ID: pub.id, Why: "等待客户端回连超时"})
		}

	case why := <-pub.rejectCh:
		pub.stopMonitor()
		pub.conn.Close()
		if why == "" {
			why = "rejected"
		}
		relay.sendEvent(eventErr{Ev: "err", ID: pub.id, Why: why})

	case <-pub.disconnectCh:
		pub.stopMonitor()
		pub.conn.Close()
		relay.sendEvent(eventErr{Ev: "err", ID: pub.id, Why: "公网连接在获准前已断开"})

	case <-timer.C:
		pub.stopMonitor()
		pub.conn.Close()
		relay.sendEvent(eventErr{Ev: "err", ID: pub.id, Why: "等待 accept 超时"})
	}
}

func (relay *Relay) removeByID(id uint64) {
	relay.regMu.Lock()
	delete(relay.byID, id)
	relay.regMu.Unlock()
}

func (relay *Relay) unregisterNonce(pub *publicConn) {
	pub.mu.Lock()
	nonce := pub.nonce
	pub.mu.Unlock()
	if nonce == "" {
		return
	}
	relay.regMu.Lock()
	if relay.byNonce[nonce] == pub {
		delete(relay.byNonce, nonce)
	}
	relay.regMu.Unlock()
}

// ---------------------------------------------------------------- 客户端回连

func (relay *Relay) acceptRelayLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go relay.handleRelayConn(conn)
	}
}

func (relay *Relay) handleRelayConn(conn net.Conn) {
	tuneTCP(conn)
	token, err := readRelayToken(conn)
	if err != nil {
		conn.Close()
		return
	}
	nonce := parseRelayToken(token)
	if nonce == "" {
		conn.Close()
		return
	}

	// nonce 一次性消费
	relay.regMu.Lock()
	pub, ok := relay.byNonce[nonce]
	if ok {
		delete(relay.byNonce, nonce)
	}
	relay.regMu.Unlock()
	if !ok {
		conn.Close()
		return
	}

	pub.mu.Lock()
	if pub.finished || pub.client != nil {
		pub.mu.Unlock()
		conn.Close()
		return
	}
	pub.client = conn
	pub.mu.Unlock()

	close(pub.clientReady)
}

// readRelayToken 读取首行（最多 128 字节，10s 超时），逐字节读取避免多读隧道数据。
func readRelayToken(conn net.Conn) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(relayTokenTimeout)); err != nil {
		return "", err
	}
	defer conn.SetReadDeadline(time.Time{})

	buffer := make([]byte, 0, relayTokenMaxLen)
	one := make([]byte, 1)
	for len(buffer) < relayTokenMaxLen {
		n, err := conn.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				break
			}
			buffer = append(buffer, one[0])
		}
		if err != nil {
			return "", err
		}
	}
	return string(buffer), nil
}

// parseRelayToken 解析 "R <nonce>" 形式的回连标识。
func parseRelayToken(token string) string {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "R ") {
		return ""
	}
	return strings.TrimSpace(token[2:])
}

// ---------------------------------------------------------------- 管道搬运

func (relay *Relay) addPipe(p *pipe) {
	relay.pipeMu.Lock()
	set := relay.pipesByUID[p.uid]
	if set == nil {
		set = make(map[*pipe]struct{})
		relay.pipesByUID[p.uid] = set
	}
	set[p] = struct{}{}
	relay.pipeMu.Unlock()
}

func (relay *Relay) removePipe(p *pipe) {
	relay.pipeMu.Lock()
	if set := relay.pipesByUID[p.uid]; set != nil {
		delete(set, p)
		if len(set) == 0 {
			delete(relay.pipesByUID, p.uid)
		}
	}
	relay.pipeMu.Unlock()
}

// startBridge 建立双向搬运，任一方向结束即收掉整条管道。
func (relay *Relay) startBridge(pub *publicConn, client net.Conn) {
	limiter := newRateLimiter(relay.userRate(pub.uid))
	p := &pipe{id: pub.id, uid: pub.uid, pub: pub.conn, client: client}
	relay.addPipe(p)
	atomic.AddInt64(&relay.pipes, 1)
	defer atomic.AddInt64(&relay.pipes, -1)

	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	var closeOnce sync.Once
	closeBoth := func() {
		p.pub.Close()
		p.client.Close()
	}

	// 先结束的方向与原因：大流量管道异常收尾时打一条日志便于定位
	var endMu sync.Mutex
	var firstEnd string
	record := func(why string) {
		endMu.Lock()
		if firstEnd == "" {
			firstEnd = why
		}
		endMu.Unlock()
	}

	// 公网 -> 客户端：结束后只做半关（FIN），让对端读到 EOF；
	// 若此刻直接 close，对向仍在途的数据会被 RST 掉，大流量必然被截断。
	go func() {
		defer waitGroup.Done()
		err := copyDirection(client, p.pub, &p.up, limiter, relay.statUp)
		record(fmt.Sprintf("公网→客户端 err=%v", err))
		closeWrite(client)
	}()
	// 客户端 -> 公网
	go func() {
		defer waitGroup.Done()
		err := copyDirection(p.pub, p.client, &p.down, limiter, relay.statDown)
		record(fmt.Sprintf("客户端→公网 err=%v", err))
		closeWrite(p.pub)
	}()

	waitGroup.Wait()
	closeOnce.Do(closeBoth) // 两个方向都结束了才真正关闭
	if p.up+p.down > 4<<20 {
		endMu.Lock()
		why := firstEnd
		endMu.Unlock()
		log.Printf("管道结束 uid=%d port=%d up=%d down=%d 先结束=%s",
			p.uid, p.id, p.up, p.down, why)
	}
	relay.removePipe(p)
	relay.sendEvent(eventDone{Ev: "done", UID: p.uid, ID: p.id, Up: p.up, Down: p.down})
}

// ---------------------------------------------------------------- 控制面客户端

// controlClient 管理与 Python 的 unix socket 连接（含断线重连）。
type controlClient struct {
	sockPath string
	relay    *Relay

	writeMu sync.Mutex
	conn    net.Conn
	writer  *bufio.Writer

	done chan struct{}
	once sync.Once
}

func newControlClient(sockPath string, relay *Relay) *controlClient {
	return &controlClient{sockPath: sockPath, relay: relay, done: make(chan struct{})}
}

func (client *controlClient) run() {
	for {
		select {
		case <-client.done:
			return
		default:
		}

		conn, err := net.DialTimeout("unix", client.sockPath, 5*time.Second)
		if err != nil {
			log.Printf("连接控制面失败，%s 后重试: %v", controlRetryInterval, err)
			if !client.sleep() {
				return
			}
			continue
		}

		client.writeMu.Lock()
		client.conn = conn
		client.writer = bufio.NewWriter(conn)
		client.writeMu.Unlock()
		log.Printf("已连接控制面: %s", client.sockPath)

		client.readLoop(conn)

		client.writeMu.Lock()
		client.conn = nil
		client.writer = nil
		client.writeMu.Unlock()
		conn.Close()

		log.Printf("控制面连接断开，%s 后重连", controlRetryInterval)
		if !client.sleep() {
			return
		}
	}
}

// sleep 可被关闭打断的等待。
func (client *controlClient) sleep() bool {
	select {
	case <-client.done:
		return false
	case <-time.After(controlRetryInterval):
		return true
	}
}

func (client *controlClient) readLoop(conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			client.handleLine(line)
		}
		if err != nil {
			return
		}
	}
}

func (client *controlClient) handleLine(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}

	var cmd command
	if err := json.Unmarshal(line, &cmd); err != nil {
		log.Printf("控制面消息解析失败，已忽略: %v", err)
		return
	}

	switch cmd.Cmd {
	case "listen":
		client.relay.cmdListen(cmd)
	case "unlisten":
		client.relay.cmdUnlisten(cmd)
	case "update":
		client.relay.cmdUpdate(cmd)
	case "kill":
		client.relay.cmdKill(cmd)
	case "accept":
		if cmd.ID != nil {
			client.relay.cmdAccept(*cmd.ID, cmd.Nonce)
		}
	case "reject":
		if cmd.ID != nil {
			client.relay.cmdReject(*cmd.ID, cmd.Why)
		}
	default:
		log.Printf("未知控制面命令，已忽略: %q", cmd.Cmd)
	}
}

// send 并发安全地发送一条换行分隔 JSON。
func (client *controlClient) send(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	data = append(data, '\n')

	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	if client.writer == nil {
		return
	}
	if _, err := client.writer.Write(data); err != nil {
		return
	}
	client.writer.Flush()
}

func (client *controlClient) reply(id *uint64, ok bool, errMsg string) {
	client.send(reply{OK: ok, ID: id, Err: errMsg})
}

func (client *controlClient) close() {
	client.once.Do(func() {
		close(client.done)
		client.writeMu.Lock()
		if client.conn != nil {
			client.conn.Close()
		}
		client.writeMu.Unlock()
	})
}

// ---------------------------------------------------------------- 关闭

func (relay *Relay) shutdown() {
	for _, listener := range relay.relayListeners {
		listener.Close()
	}

	relay.mu.Lock()
	for _, entry := range relay.listeners {
		entry.ln.Close()
	}
	relay.listeners = make(map[string]*listenerEntry)
	relay.mu.Unlock()

	relay.pipeMu.Lock()
	var all []*pipe
	for _, set := range relay.pipesByUID {
		for p := range set {
			all = append(all, p)
		}
	}
	relay.pipeMu.Unlock()
	for _, p := range all {
		p.pub.Close()
		p.client.Close()
	}

	// 留一点时间让 done 事件发出
	if relay.control != nil {
		time.Sleep(200 * time.Millisecond)
		relay.control.close()
	}
}

// ---------------------------------------------------------------- 入口

func main() {
	sockPath := flag.String("sock", "", "控制面 unix socket 路径")
	relayPort := flag.Int("relay-port", 18282, "中继（客户端回连）监听端口")
	certFile := flag.String("cert", "", "TLS 证书（与 -key 同时提供时启用 TLS）")
	keyFile := flag.String("key", "", "TLS 私钥（与 -cert 同时提供时启用 TLS）")
	statFile := flag.String("stat-file", "", "块大小埋点输出文件（留空关闭）")
	bulkPauseMs := flag.Int("bulk-pause-ms", 4, "攒批停读基准毫秒数（0 = 不攒批）")
	relayBind := flag.String("relay-bind", "", "中继监听地址（逗号分隔；留空 = 双栈通配）")
	flag.BoolVar(&spliceEnable, "splice", false,
		"内核 splice 零拷贝（高吞吐链路可开；WAN 瓶颈链路实测反而劣化，默认关闭）")
	flag.Parse()

	if *sockPath == "" {
		log.Fatal("必须指定 -sock 控制面 socket 路径")
	}
	if *bulkPauseMs > 0 {
		bulkPause = time.Duration(*bulkPauseMs) * time.Millisecond
	} else {
		bulkPause = 0
	}

	relay := newRelay()

	// 中继监听：客户端带 nonce 回连的入口。默认由控制面收敛到本机业务地址
	// （-relay-bind），不在用户 /128 上占端口；留空时保持双栈通配。
	relayPortText := strconv.Itoa(*relayPort)
	var addresses []string
	if strings.TrimSpace(*relayBind) == "" {
		addresses = []string{":" + relayPortText}
	} else {
		for _, item := range strings.Split(*relayBind, ",") {
			if item = strings.TrimSpace(item); item != "" {
				addresses = append(addresses, net.JoinHostPort(item, relayPortText))
			}
		}
	}

	var certificate *tls.Certificate
	if *certFile != "" && *keyFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("加载 TLS 证书失败: %v", err)
		}
		certificate = &cert
	}
	mode := "明文"
	if certificate != nil {
		mode = "TLS"
	}

	for _, address := range addresses {
		listener, err := listenOn(address)
		if err != nil {
			log.Printf("中继监听失败 %s: %v", address, err)
			continue
		}
		if certificate != nil {
			listener = tls.NewListener(listener, &tls.Config{
				Certificates: []tls.Certificate{*certificate},
				MinVersion:   tls.VersionTLS12,
			})
		}
		relay.relayListeners = append(relay.relayListeners, listener)
		log.Printf("中继监听已启用%s: %s", mode, address)
		go relay.acceptRelayLoop(listener)
	}
	if len(relay.relayListeners) == 0 {
		log.Fatalf("中继监听全部失败: %v", addresses)
	}

	// 控制面客户端
	relay.control = newControlClient(*sockPath, relay)
	go relay.control.run()

	// 块大小埋点：仅指定文件时启用，正常路径（statUp/statDown 为 nil）零开销
	if *statFile != "" {
		file, err := os.OpenFile(*statFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Printf("埋点文件不可写，已关闭块大小统计: %v", err)
		} else {
			relay.statUp, relay.statDown = &dirStats{}, &dirStats{}
			reporter := &statReporter{file: file, path: *statFile, up: relay.statUp,
				down: relay.statDown, pipes: &relay.pipes}
			go reporter.run()
			log.Printf("块大小埋点已启用: %s", *statFile)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Printf("收到退出信号，开始优雅关闭")
	relay.shutdown()
	log.Printf("已退出")
}
