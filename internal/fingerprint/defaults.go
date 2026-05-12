package fingerprint

// DefaultRules 内置常见 mDNS 设备指纹。
//
// 规则来源（资深开发者经验）：
//   - QNAP: 通过私有服务 `_qdiscover._tcp.local` 直接确认；TXT 含 model=TS-/TVS- 等
//   - Synology: TXT 含 model=DS/RS/DSM 等关键字（_smb / _http）
//   - Apple 设备: _airplay / _raop / _companion-link, TXT model=MacBook/iPad/iPhone
//   - HomeKit: _hap._tcp.local
//   - 打印机: _ipp / _ipps / _printer
//   - Chromecast: _googlecast._tcp.local
//   - Workstation (Linux/Avahi): _workstation._tcp.local
//
// 团队后续可通过 AddRules 注入自家设备规则，无需修改本文件。
func DefaultRules() []Rule {
	return []Rule{
		// ---------- NAS ----------
		{
			ID: "qnap.qdiscover", Vendor: "QNAP", Product: "QNAP NAS", Category: CategoryNAS,
			Priority: 100, ServiceType: "qdiscover",
		},
		{
			ID: "qnap.txt-model", Vendor: "QNAP", Product: "QNAP NAS", Category: CategoryNAS,
			Priority: 95, TXTContains: []string{"displaymodel=ts-"},
		},
		{
			ID: "qnap.txt-fwbuild", Vendor: "QNAP", Product: "QNAP NAS", Category: CategoryNAS,
			Priority: 90, TXTContains: []string{"fwbuildnum="},
		},
		{
			ID: "synology.txt-model", Vendor: "Synology", Product: "Synology DiskStation", Category: CategoryNAS,
			Priority: 95, TXTContains: []string{"model=ds"},
		},
		{
			ID: "synology.dsm", Vendor: "Synology", Product: "Synology DSM", Category: CategoryNAS,
			Priority: 90, TXTContains: []string{"vendor=synology"},
		},

		// ---------- Apple Host ----------
		{
			ID: "apple.airplay-mac", Vendor: "Apple", Product: "Mac (AirPlay)", Category: CategoryAppleHost,
			Priority: 80, ServiceType: "airplay", TXTContains: []string{"model=macbook"},
		},
		{
			ID: "apple.airplay-ipad", Vendor: "Apple", Product: "iPad (AirPlay)", Category: CategoryAppleHost,
			Priority: 80, ServiceType: "airplay", TXTContains: []string{"model=ipad"},
		},
		{
			ID: "apple.airplay-iphone", Vendor: "Apple", Product: "iPhone (AirPlay)", Category: CategoryAppleHost,
			Priority: 80, ServiceType: "airplay", TXTContains: []string{"model=iphone"},
		},
		{
			ID: "apple.companion-link", Vendor: "Apple", Product: "Apple Continuity", Category: CategoryAppleHost,
			Priority: 60, ServiceType: "companion-link",
		},
		{
			ID: "apple.raop", Vendor: "Apple", Product: "AirPlay Audio (RAOP)", Category: CategoryAppleHost,
			Priority: 55, ServiceType: "raop",
		},
		{
			ID: "apple.afp", Vendor: "Apple/Compat", Product: "AFP Server", Category: CategoryNAS,
			Priority: 40, ServiceType: "afpovertcp",
		},

		// ---------- Smart Home / IoT ----------
		{
			ID: "homekit.hap", Vendor: "HomeKit Accessory", Product: "HAP Device", Category: CategorySmartHome,
			Priority: 70, ServiceType: "hap",
		},

		// ---------- Media Cast ----------
		{
			ID: "google.cast", Vendor: "Google", Product: "Chromecast", Category: CategoryMediaCast,
			Priority: 70, ServiceType: "googlecast",
		},
		{
			ID: "spotify.connect", Vendor: "Spotify", Product: "Spotify Connect", Category: CategoryMediaCast,
			Priority: 50, ServiceType: "spotify-connect",
		},

		// ---------- Printer ----------
		{
			ID: "printer.ipp", Vendor: "IPP Printer", Product: "Network Printer", Category: CategoryPrinter,
			Priority: 60, ServiceType: "ipp",
		},
		{
			ID: "printer.ipps", Vendor: "IPP Printer", Product: "Secure Network Printer", Category: CategoryPrinter,
			Priority: 60, ServiceType: "ipps",
		},
		{
			ID: "printer.line", Vendor: "Generic Printer", Product: "LPD Printer", Category: CategoryPrinter,
			Priority: 50, ServiceType: "printer",
		},

		// ---------- Workstation ----------
		{
			ID: "linux.workstation", Vendor: "Linux/Avahi", Product: "Workstation", Category: CategoryWorkstation,
			Priority: 30, ServiceType: "workstation",
		},
	}
}
