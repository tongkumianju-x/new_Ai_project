package mdns

// CommonServices 是网站测绘最常见的 mDNS 服务类型。
//
// 顺序是有讲究的：
//   - _services._dns-sd._udp.local 是 "服务枚举"，用来拉所有服务清单（DNS-SD）；
//   - 后续服务覆盖了 NAS、打印机、苹果设备、媒体服务等典型企业资产；
//   - 这与示例输出中的 services 类型保持一致：workstation/http/smb/qdiscover/device-info/afpovertcp。
var CommonServices = []string{
	"_services._dns-sd._udp.local",
	"_workstation._tcp.local",
	"_http._tcp.local",
	"_https._tcp.local",
	"_smb._tcp.local",
	"_afpovertcp._tcp.local",
	"_device-info._tcp.local",
	"_qdiscover._tcp.local",
	"_ipp._tcp.local",
	"_ipps._tcp.local",
	"_printer._tcp.local",
	"_airplay._tcp.local",
	"_raop._tcp.local",
	"_googlecast._tcp.local",
	"_companion-link._tcp.local",
	"_homekit._tcp.local",
	"_ssh._tcp.local",
	"_sftp-ssh._tcp.local",
	"_rfb._tcp.local",        // VNC
	"_nfs._tcp.local",
	"_webdav._tcp.local",
	"_atc._tcp.local",        // Apple TV
	"_hap._tcp.local",
	"_spotify-connect._tcp.local",
}

// ShortServiceName 从 "_http._tcp.local" 提取 "http"
func ShortServiceName(full string) string {
	// 取第一个以下划线开头的标签，去掉前缀 _
	for i := 0; i < len(full); i++ {
		if full[i] == '.' {
			name := full[:i]
			if len(name) > 0 && name[0] == '_' {
				return name[1:]
			}
			return name
		}
	}
	if len(full) > 0 && full[0] == '_' {
		return full[1:]
	}
	return full
}

// ServiceTransport 返回服务对应的传输层（tcp/udp/-）
// 解析形如 _http._tcp.local
func ServiceTransport(full string) string {
	// 找第二段
	first := -1
	for i := 0; i < len(full); i++ {
		if full[i] == '.' {
			if first == -1 {
				first = i
				continue
			}
			seg := full[first+1 : i]
			if len(seg) > 0 && seg[0] == '_' {
				return seg[1:]
			}
			return seg
		}
	}
	return ""
}
