// Package scanner 负责将 mDNS 协议层的 RR 聚合为"资产"（Asset）模型。
//
// 一个 Asset 表示一台主机（按 hostname 或 IP 聚合），其下包含若干 Service。
// 每个 Service 对应 "<port>/<transport> <serviceName>" 的输出节，并携带深度 banner（TXT 键值对）。
package scanner

import (
	"net"
	"sort"
	"strings"
)

// Service 表示资产上的一个 mDNS 服务实例。
type Service struct {
	Type      string   // e.g. "workstation"、"http"
	Transport string   // tcp / udp
	Port      int
	Instance  string   // SRV 实例名，对外展示为 Name=...
	TXT       []string // 原始 TXT 键值对（按 "key=value" 形式存储）
	TTL       uint32
}

// Asset 表示一台被发现的主机。
type Asset struct {
	Hostname string
	IPv4     net.IP
	IPv6     net.IP
	TTL      uint32
	Services []*Service
	// PTR Answers 直接从响应里提取出来，用于 answers 段输出
	PTRAnswers []string
}

// Key 用于在 store 中聚合资产：优先按 hostname，否则按 IP。
func (a *Asset) Key() string {
	if a.Hostname != "" {
		return strings.ToLower(a.Hostname)
	}
	if a.IPv4 != nil {
		return a.IPv4.String()
	}
	if a.IPv6 != nil {
		return a.IPv6.String()
	}
	return ""
}

// Store 是资产聚合容器，并发安全在 scanner 上层处理。
type Store struct {
	assets map[string]*Asset
	order  []string
}

func NewStore() *Store {
	return &Store{assets: map[string]*Asset{}}
}

// Upsert 按 key 合并资产；若已存在则做字段补充。
func (s *Store) Upsert(a *Asset) *Asset {
	key := a.Key()
	if key == "" {
		return a
	}
	if existed, ok := s.assets[key]; ok {
		mergeAsset(existed, a)
		return existed
	}
	s.assets[key] = a
	s.order = append(s.order, key)
	return a
}

// All 返回按发现顺序排列的资产列表。
func (s *Store) All() []*Asset {
	out := make([]*Asset, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, s.assets[k])
	}
	return out
}

func mergeAsset(dst, src *Asset) {
	if dst.Hostname == "" {
		dst.Hostname = src.Hostname
	}
	if dst.IPv4 == nil && src.IPv4 != nil {
		dst.IPv4 = src.IPv4
	}
	if dst.IPv6 == nil && src.IPv6 != nil {
		dst.IPv6 = src.IPv6
	}
	if src.TTL > 0 && (dst.TTL == 0 || src.TTL < dst.TTL) {
		dst.TTL = src.TTL
	}
	for _, ns := range src.Services {
		if !hasService(dst.Services, ns) {
			dst.Services = append(dst.Services, ns)
		} else {
			// 合并 TXT
			for _, ds := range dst.Services {
				if sameService(ds, ns) {
					ds.TXT = mergeTXT(ds.TXT, ns.TXT)
				}
			}
		}
	}
	for _, p := range src.PTRAnswers {
		if !contains(dst.PTRAnswers, p) {
			dst.PTRAnswers = append(dst.PTRAnswers, p)
		}
	}
	// services 排序：按 port + type
	sort.SliceStable(dst.Services, func(i, j int) bool {
		if dst.Services[i].Port != dst.Services[j].Port {
			return dst.Services[i].Port < dst.Services[j].Port
		}
		return dst.Services[i].Type < dst.Services[j].Type
	})
}

func hasService(list []*Service, s *Service) bool {
	for _, x := range list {
		if sameService(x, s) {
			return true
		}
	}
	return false
}

func sameService(a, b *Service) bool {
	return a.Type == b.Type && a.Port == b.Port && a.Transport == b.Transport
}

func mergeTXT(a, b []string) []string {
	seen := map[string]struct{}{}
	for _, x := range a {
		seen[x] = struct{}{}
	}
	for _, x := range b {
		if _, ok := seen[x]; !ok {
			seen[x] = struct{}{}
			a = append(a, x)
		}
	}
	return a
}

func contains(list []string, x string) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}
