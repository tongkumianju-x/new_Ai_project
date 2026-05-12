package scanner

import (
	"net"
	"strings"

	"github.com/newAIProject/mdns-scanner/internal/mdns"
)

// srvInfo 在包内共享的 SRV 索引项。
type srvInfo struct {
	port      uint16
	target    string
	ttl       uint32
	transport string
	svcType   string
}

// MergeMessages 是 mergeMessages 的导出版本，便于外部测试与离线分析工具调用。
func MergeMessages(sourceIP net.IP, msgs []*mdns.Message) []*Asset {
	return mergeMessages(sourceIP, msgs)
}

// mergeMessages 把若干 mDNS 响应聚合为 Asset 列表。
//
// 思路：
//  1. 第一遍：扫所有 RR，构建 hostname -> IPv4/IPv6/TTL 索引；
//     PTR 答案直接收集进 PTRAnswers；
//     SRV 记录构建 instanceName -> {port, transport, target, type}；
//     TXT 记录构建 instanceName -> []string；
//  2. 第二遍：基于 PTR -> Instance 列表创建 Service，挂到 Asset 下；
//     若没有 SRV（个别简单设备），就根据 PTR 直接生成空 banner 的 service。
//  3. PTR Answer 段在最后写入时去重，并保持发现顺序。
func mergeMessages(sourceIP net.IP, msgs []*mdns.Message) []*Asset {
	hostV4 := map[string]net.IP{}
	hostV6 := map[string]net.IP{}
	hostTTL := map[string]uint32{}
	srvByInst := map[string]srvInfo{}
	txtByInst := map[string][]string{}
	ptrAnswers := []string{}                     // 服务类型列表（保持发现顺序）
	ptrInstances := map[string][]string{}        // serviceType -> instanceNames

	for _, m := range msgs {
		for _, rr := range m.Answers {
			if rr.Type == mdns.TypePTR {
				st := strings.TrimSuffix(rr.Name, ".")
				inst := strings.TrimSuffix(rr.Target, ".")
				ptrInstances[st] = appendUnique(ptrInstances[st], inst)
				if !contains(ptrAnswers, st) {
					ptrAnswers = append(ptrAnswers, st)
				}
			}
		}
		for _, rr := range m.AllRecords() {
			switch rr.Type {
			case mdns.TypeA:
				host := strings.TrimSuffix(rr.Name, ".")
				if _, ok := hostV4[host]; !ok && rr.IP != nil {
					hostV4[host] = rr.IP
				}
				if rr.TTL > 0 && (hostTTL[host] == 0 || rr.TTL < hostTTL[host]) {
					hostTTL[host] = rr.TTL
				}
			case mdns.TypeAAAA:
				host := strings.TrimSuffix(rr.Name, ".")
				if _, ok := hostV6[host]; !ok && rr.IP != nil {
					hostV6[host] = rr.IP
				}
				if rr.TTL > 0 && (hostTTL[host] == 0 || rr.TTL < hostTTL[host]) {
					hostTTL[host] = rr.TTL
				}
			case mdns.TypeSRV:
				inst := strings.TrimSuffix(rr.Name, ".")
				svcType, transport := splitInstance(inst)
				srvByInst[inst] = srvInfo{
					port:      rr.Port,
					target:    strings.TrimSuffix(rr.Target, "."),
					ttl:       rr.TTL,
					transport: transport,
					svcType:   svcType,
				}
			case mdns.TypeTXT:
				inst := strings.TrimSuffix(rr.Name, ".")
				txtByInst[inst] = append(txtByInst[inst], rr.TXT...)
			}
		}
		for _, rr := range m.Additional {
			if rr.Type == mdns.TypePTR {
				st := strings.TrimSuffix(rr.Name, ".")
				inst := strings.TrimSuffix(rr.Target, ".")
				ptrInstances[st] = appendUnique(ptrInstances[st], inst)
			}
		}
	}

	mainHost := pickMainHost(srvByInst, hostV4, hostV6, sourceIP)
	if mainHost == "" && sourceIP != nil {
		mainHost = sourceIP.String()
	}

	a := &Asset{
		Hostname:   mainHost,
		PTRAnswers: ptrAnswers,
	}
	if ip, ok := hostV4[mainHost]; ok {
		a.IPv4 = ip
	} else if sourceIP != nil && sourceIP.To4() != nil {
		a.IPv4 = sourceIP
	}
	if ip, ok := hostV6[mainHost]; ok {
		a.IPv6 = ip
	}
	if ttl, ok := hostTTL[mainHost]; ok {
		a.TTL = ttl
	}

	for _, st := range ptrAnswers {
		instances := ptrInstances[st]
		if len(instances) == 0 {
			continue
		}
		// 过滤 _services._dns-sd._udp.local 这种"元枚举"答案
		if strings.HasPrefix(st, "_services.") {
			continue
		}
		for _, inst := range instances {
			info, hasSRV := srvByInst[inst]
			svcType, transport := info.svcType, info.transport
			if svcType == "" {
				svcType = mdns.ShortServiceName(st)
				transport = mdns.ServiceTransport(st)
			}
			port := int(info.port)
			if !hasSRV {
				port = 0
			}
			sv := &Service{
				Type:      svcType,
				Transport: transport,
				Port:      port,
				Instance:  shortInstance(inst),
				TXT:       txtByInst[inst],
				TTL:       info.ttl,
				Target:    info.target,
			}
			a.Services = append(a.Services, sv)
			if info.target != "" {
				a.SRVTargets = appendUnique(a.SRVTargets, info.target)
			}
		}
	}

	if a.Hostname == "" && a.IPv4 == nil && len(a.Services) == 0 {
		return nil
	}
	return []*Asset{a}
}

// splitInstance 从 "Name._http._tcp.local" 拆出 (svcType, transport)
func splitInstance(inst string) (svcType, transport string) {
	parts := strings.Split(inst, ".")
	for i, p := range parts {
		if strings.HasPrefix(p, "_") {
			svcType = strings.TrimPrefix(p, "_")
			if i+1 < len(parts) && strings.HasPrefix(parts[i+1], "_") {
				transport = strings.TrimPrefix(parts[i+1], "_")
			}
			return
		}
	}
	return "", ""
}

func shortInstance(inst string) string {
	parts := strings.Split(inst, ".")
	if len(parts) == 0 {
		return inst
	}
	return parts[0]
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func pickMainHost(
	srv map[string]srvInfo,
	v4 map[string]net.IP,
	v6 map[string]net.IP,
	sourceIP net.IP,
) string {
	count := map[string]int{}
	for _, s := range srv {
		if s.target != "" {
			count[s.target]++
		}
	}
	var best string
	var bestN int
	for h, n := range count {
		if n > bestN {
			best = h
			bestN = n
		}
	}
	if best != "" {
		return best
	}
	if sourceIP != nil {
		for h, ip := range v4 {
			if ip.Equal(sourceIP) {
				return h
			}
		}
	}
	for h := range v4 {
		return h
	}
	for h := range v6 {
		return h
	}
	return ""
}
