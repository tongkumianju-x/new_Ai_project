// Package iprange 提供 CIDR 网段与端口范围的展开能力。
//
// 设计要点：
//  1. CIDR 展开避免一次性分配巨大切片，使用迭代器模式（Next）；
//  2. 端口范围支持 "5353"、"1-1024"、"80,443,5353" 三种语法；
//  3. 所有 IP 操作基于 net.IP，IPv4 与 IPv6 分开处理。
package iprange

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IPIterator 按需产生 IP，避免在 /16 这类大网段中爆内存。
type IPIterator struct {
	current net.IP
	end     net.IP
	done    bool
}

// NewFromCIDR 解析 CIDR（如 192.168.1.0/24），返回迭代器。
// 单 IP（不带 /xx）也会被识别为 /32 或 /128。
func NewFromCIDR(cidr string) (*IPIterator, error) {
	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", cidr)
		}
		if ip.To4() != nil {
			cidr = cidr + "/32"
		} else {
			cidr = cidr + "/128"
		}
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cidr %s: %w", cidr, err)
	}
	start := ipNet.IP
	end := lastIP(ipNet)
	return &IPIterator{
		current: dupIP(start),
		end:     end,
	}, nil
}

// Next 返回下一个 IP，遍历完毕返回 nil。
func (it *IPIterator) Next() net.IP {
	if it.done {
		return nil
	}
	out := dupIP(it.current)
	if it.current.Equal(it.end) {
		it.done = true
		return out
	}
	incIP(it.current)
	return out
}

// Count 估算迭代器剩余 IP 数（仅供日志显示，不精确大网段）。
func (it *IPIterator) Count() int {
	// 简单实现：只对 /20 以内的 IPv4 统计精确值
	if it.current.To4() == nil {
		return -1
	}
	a := ip4ToUint32(it.current)
	b := ip4ToUint32(it.end)
	if b < a {
		return 0
	}
	return int(b-a) + 1
}

// ParsePorts 解析端口表达式。
// 支持 "5353"、"1-1024"、"80,443,5353-5400" 等组合。
func ParsePorts(expr string) ([]int, error) {
	if expr == "" {
		return nil, fmt.Errorf("empty port expression")
	}
	seen := make(map[int]struct{})
	var result []int
	for _, segment := range strings.Split(expr, ",") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		if strings.Contains(segment, "-") {
			parts := strings.SplitN(segment, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid range: %s", segment)
			}
			if lo < 0 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("port range out of bounds: %s", segment)
			}
			for p := lo; p <= hi; p++ {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					result = append(result, p)
				}
			}
		} else {
			p, err := strconv.Atoi(segment)
			if err != nil || p < 0 || p > 65535 {
				return nil, fmt.Errorf("invalid port: %s", segment)
			}
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				result = append(result, p)
			}
		}
	}
	return result, nil
}

// --- helpers ---

func dupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func lastIP(n *net.IPNet) net.IP {
	last := dupIP(n.IP)
	for i := range last {
		last[i] |= ^n.Mask[i]
	}
	return last
}

func ip4ToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}
