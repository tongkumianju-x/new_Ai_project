// Package scanner 实现 mDNS 扫描调度。
//
// 扫描策略（重要！）：
//
//	mDNS 标准是组播协议（224.0.0.251:5353 / [FF02::FB]:5353），但在网段测绘场景下：
//	  1) 目标网段往往跨子网，组播无法穿透；
//	  2) 我们对每个 IP 直接发送 "单播 mDNS 查询"（unicast-response 标志位 + 目标 5353 端口）；
//	  3) 大多数 mDNS 设备（Bonjour / Avahi / QNAP / Synology 等）都会回应单播探测；
//	  4) 同时也保留组播探测能力，用于本地 LAN 段扫描。
//
// 端口范围参数（--ports）的语义：
//
//	mDNS 协议本身固定在 UDP 5353。但用户可能输入任意端口范围，我们的处理：
//	  - 若 5353 在范围内：执行 mDNS 探测；
//	  - 同时输出报文中所携带的 SRV 服务端口（不论是否在 --ports 范围内都展示），
//	    再用 --ports 做"仅展示落在范围内的服务"的过滤（可选 strict 模式）。
//
//	这样的设计让 CLI 同时具备"网络发现"和"端口范围筛选"两种能力，符合资产测绘的实际需求。
package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/newAIProject/mdns-scanner/internal/mdns"
	"github.com/newAIProject/mdns-scanner/pkg/iprange"
)

// Options 扫描配置。
type Options struct {
	CIDR        string        // 目标网段，如 192.168.1.0/24
	Ports       []int         // 端口范围（用于过滤展示服务）
	StrictPorts bool          // true: 仅输出落在 Ports 范围内的服务
	Timeout     time.Duration // 单 IP 等待响应超时
	Concurrency int           // 并发 IP 数
	Multicast   bool          // 是否额外发起组播探测
	Iface       string        // 组播探测使用的网卡
	Verbose     bool

	// FingerprintHook 在资产合并完成后调用，用于注入指纹识别等后处理。
	// 设计为 hook 是为了避免 scanner 包反向依赖 fingerprint 包。
	FingerprintHook func([]*Asset)
}

// Scanner 主扫描器
type Scanner struct {
	opts Options
	log  func(format string, args ...interface{})
}

// New 构造扫描器。
func New(opts Options, logger func(string, ...interface{})) *Scanner {
	if opts.Timeout == 0 {
		opts.Timeout = 1500 * time.Millisecond
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 64
	}
	if logger == nil {
		logger = func(string, ...interface{}) {}
	}
	return &Scanner{opts: opts, log: logger}
}

// Run 执行扫描，返回聚合后的资产 store。
func (s *Scanner) Run(ctx context.Context) (*Store, error) {
	store := NewStore()
	mu := sync.Mutex{}

	// 1) 单播探测网段每个 IP
	if s.opts.CIDR != "" {
		it, err := iprange.NewFromCIDR(s.opts.CIDR)
		if err != nil {
			return nil, fmt.Errorf("parse cidr: %w", err)
		}
		s.log("scanning CIDR %s (approx %d hosts)", s.opts.CIDR, it.Count())

		sem := make(chan struct{}, s.opts.Concurrency)
		var wg sync.WaitGroup

		for {
			ip := it.Next()
			if ip == nil {
				break
			}
			select {
			case <-ctx.Done():
				goto wait
			default:
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(target net.IP) {
				defer wg.Done()
				defer func() { <-sem }()
				assets, err := s.probeUnicast(ctx, target)
				if err != nil {
					if s.opts.Verbose {
						s.log("probe %s: %v", target, err)
					}
					return
				}
				mu.Lock()
				for _, a := range assets {
					store.Upsert(a)
				}
				mu.Unlock()
			}(ip)
		}
	wait:
		wg.Wait()
	}

	// 2) 组播探测（可选）
	if s.opts.Multicast {
		s.log("multicast probing on link-local mDNS group ...")
		assets, err := s.probeMulticast(ctx)
		if err != nil {
			s.log("multicast probe error: %v", err)
		}
		mu.Lock()
		for _, a := range assets {
			store.Upsert(a)
		}
		mu.Unlock()
	}

	// 3) 端口过滤
	if s.opts.StrictPorts && len(s.opts.Ports) > 0 {
		portSet := map[int]struct{}{}
		for _, p := range s.opts.Ports {
			portSet[p] = struct{}{}
		}
		for _, a := range store.All() {
			filtered := a.Services[:0]
			for _, sv := range a.Services {
				if _, ok := portSet[sv.Port]; ok {
					filtered = append(filtered, sv)
				}
			}
			a.Services = filtered
		}
	}

	// 4) 指纹识别 hook
	if s.opts.FingerprintHook != nil {
		s.opts.FingerprintHook(store.All())
	}

	return store, nil
}

// probeUnicast 对单个目标 IP 的 5353 端口发起 mDNS 查询。
func (s *Scanner) probeUnicast(ctx context.Context, target net.IP) ([]*Asset, error) {
	// 端口范围里若不包含 5353，仍然发包（用户的 --ports 是用来"过滤展示"的）
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(s.opts.Timeout)
	_ = conn.SetDeadline(deadline)

	dest := &net.UDPAddr{IP: target, Port: 5353}
	pkt, err := mdns.BuildQuery(mdns.CommonServices, mdns.TypeANY, true)
	if err != nil {
		return nil, fmt.Errorf("build query: %w", err)
	}
	if _, err := conn.WriteToUDP(pkt, dest); err != nil {
		return nil, fmt.Errorf("write udp: %w", err)
	}

	buf := make([]byte, 9000)
	var responses []*mdns.Message
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			break
		}
		msg, perr := mdns.Parse(buf[:n])
		if perr != nil {
			continue
		}
		responses = append(responses, msg)
		if time.Now().After(deadline) {
			break
		}
	}
	if len(responses) == 0 {
		return nil, nil
	}
	return mergeMessages(target, responses), nil
}

// probeMulticast 在 224.0.0.251:5353 上做组播查询并收集回包。
func (s *Scanner) probeMulticast(ctx context.Context) ([]*Asset, error) {
	addr := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("listen multicast: %w", err)
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(1 << 20)

	deadline := time.Now().Add(s.opts.Timeout * 3)
	_ = conn.SetReadDeadline(deadline)

	// 发送
	out, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("dial multicast: %w", err)
	}
	defer out.Close()
	pkt, _ := mdns.BuildQuery(mdns.CommonServices, mdns.TypeANY, false)
	_, _ = out.Write(pkt)

	buf := make([]byte, 9000)
	var responses []*mdns.Message
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		msg, perr := mdns.Parse(buf[:n])
		if perr != nil {
			continue
		}
		// 标记来源 IP，用于补全 IPv4
		_ = src
		responses = append(responses, msg)
	}
	return mergeMessages(nil, responses), nil
}
