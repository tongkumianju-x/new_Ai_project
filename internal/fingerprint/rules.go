// Package fingerprint 基于 mDNS 服务的 TXT / PTR / SRV target 等字段识别设备厂商与产品。
//
// 设计取舍（资深开发者注释）：
//   1. 规则用 Go 结构体硬编码 + 可注入扩展，兼顾"开箱即用"和"业务可定制"；
//   2. 匹配维度：service-type、TXT key=value 子串、SRV target 主机名子串；
//   3. 同一资产可命中多条规则，按 Priority 取最高的作为主指纹；
//      其它命中作为 Tags 一起返回，方便资产画像；
//   4. 匹配是大小写不敏感的（mDNS 字段大小写并不严格规范，QNAP/Synology/Apple 都有混用）。
package fingerprint

import (
	"strings"
)

// Category 设备品类（粗分类，便于资产管理）
type Category string

const (
	CategoryNAS        Category = "nas"
	CategoryPrinter    Category = "printer"
	CategoryAppleHost  Category = "apple-host"
	CategoryMediaCast  Category = "media-cast"
	CategorySmartHome  Category = "smart-home"
	CategoryWorkstation Category = "workstation"
	CategoryUnknown    Category = "unknown"
)

// Match 表示一条规则命中的结果。
type Match struct {
	Vendor   string
	Product  string
	Category Category
	Priority int    // 数字越大优先级越高
	RuleID   string // 命中的规则 ID，便于排查
}

// Rule 一条指纹规则。所有字段为 AND 关系。
//
//   - ServiceType: 形如 "qdiscover" / "http" / "afpovertcp"，不带下划线和 .local
//   - TXTContains: 任一 TXT 串包含这些子串（AND）；用 "key=value" 或仅 "key=" 都可以
//   - TargetContains: SRV target 主机名包含这些子串
//   - HostnameContains: 资产 hostname 包含子串
//
// 字段为空表示"不限制"。
type Rule struct {
	ID               string
	Vendor           string
	Product          string
	Category         Category
	Priority         int
	ServiceType      string
	TXTContains      []string
	TargetContains   []string
	HostnameContains []string
}

// AssetView 是 fingerprint 引擎需要的资产快照（避免直接依赖 scanner 包，防止循环引用）。
type AssetView struct {
	Hostname string
	Services []ServiceView
}

// ServiceView 服务快照
type ServiceView struct {
	Type      string
	Transport string
	Target    string
	TXT       []string
}

// Engine 指纹引擎
type Engine struct {
	rules []Rule
}

// NewEngineWithDefaults 加载内置规则
func NewEngineWithDefaults() *Engine {
	e := &Engine{}
	e.AddRules(DefaultRules()...)
	return e
}

// AddRules 注入业务规则；可在运行时多次调用
func (e *Engine) AddRules(rs ...Rule) {
	e.rules = append(e.rules, rs...)
}

// Match 对资产做指纹识别，返回 (主指纹, 全部命中)。
// 若无规则命中，主指纹为零值且 Category=Unknown。
func (e *Engine) Match(a AssetView) (Match, []Match) {
	var hits []Match
	for _, r := range e.rules {
		if ok, svcType := r.matches(a); ok {
			hits = append(hits, Match{
				Vendor:   r.Vendor,
				Product:  withType(r.Product, svcType),
				Category: r.Category,
				Priority: r.Priority,
				RuleID:   r.ID,
			})
		}
	}
	if len(hits) == 0 {
		return Match{Category: CategoryUnknown}, nil
	}
	primary := hits[0]
	for _, h := range hits[1:] {
		if h.Priority > primary.Priority {
			primary = h
		}
	}
	return primary, hits
}

func withType(product, svcType string) string {
	if product == "" || svcType == "" {
		return product
	}
	return product
}

// matches 判断规则是否命中资产，并返回首个命中的服务类型（用于诊断）。
func (r Rule) matches(a AssetView) (bool, string) {
	host := strings.ToLower(a.Hostname)
	if len(r.HostnameContains) > 0 && !allContain(host, r.HostnameContains) {
		return false, ""
	}
	for _, s := range a.Services {
		if r.ServiceType != "" && !strings.EqualFold(s.Type, r.ServiceType) {
			continue
		}
		target := strings.ToLower(s.Target)
		if len(r.TargetContains) > 0 && !allContain(target, r.TargetContains) {
			continue
		}
		if len(r.TXTContains) > 0 && !txtAllContain(s.TXT, r.TXTContains) {
			continue
		}
		// 此条服务通过所有约束 → 规则命中
		return true, s.Type
	}
	// 没有 ServiceType 约束时，hostname 已经满足即可
	if r.ServiceType == "" && len(r.TXTContains) == 0 && len(r.TargetContains) == 0 && len(r.HostnameContains) > 0 {
		return true, ""
	}
	return false, ""
}

func allContain(haystack string, needles []string) bool {
	for _, n := range needles {
		if !strings.Contains(haystack, strings.ToLower(n)) {
			return false
		}
	}
	return true
}

func txtAllContain(txt []string, needles []string) bool {
	low := make([]string, len(txt))
	for i, t := range txt {
		low[i] = strings.ToLower(t)
	}
	for _, n := range needles {
		need := strings.ToLower(n)
		hit := false
		for _, t := range low {
			if strings.Contains(t, need) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}
