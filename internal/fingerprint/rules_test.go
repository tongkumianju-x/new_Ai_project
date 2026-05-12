package fingerprint

import (
	"testing"
)

// TestQNAPDetection: 用题目示例的 QNAP NAS 数据测试指纹引擎能否准确识别。
func TestQNAPDetection(t *testing.T) {
	asset := AssetView{
		Hostname: "slw-nas.local",
		Services: []ServiceView{
			{Type: "workstation", Transport: "tcp", Target: "slw-nas.local"},
			{Type: "http", Transport: "tcp", Target: "slw-nas.local", TXT: []string{"path=/"}},
			{Type: "smb", Transport: "tcp", Target: "slw-nas.local"},
			{Type: "qdiscover", Transport: "tcp", Target: "slw-nas.local", TXT: []string{
				"accessType=https", "accessPort=86", "model=TS-X64",
				"displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214",
			}},
			{Type: "afpovertcp", Transport: "tcp", Target: "slw-nas.local"},
			{Type: "device-info", Target: "", TXT: []string{"model=Xserve"}},
		},
	}
	eng := NewEngineWithDefaults()
	primary, hits := eng.Match(asset)
	if primary.Vendor != "QNAP" {
		t.Fatalf("primary vendor = %q, want QNAP. hits=%+v", primary.Vendor, hits)
	}
	if primary.Category != CategoryNAS {
		t.Fatalf("category = %q, want %q", primary.Category, CategoryNAS)
	}
	// 应该至少命中 qdiscover + displaymodel + fwbuildnum 三条
	if len(hits) < 3 {
		t.Fatalf("hits = %d, want >= 3 (multi-rule)", len(hits))
	}
}

func TestSynologyDetection(t *testing.T) {
	asset := AssetView{
		Hostname: "ds920.local",
		Services: []ServiceView{
			{Type: "smb", Target: "ds920.local", TXT: []string{"model=DS920+", "vendor=Synology"}},
			{Type: "afpovertcp", Target: "ds920.local"},
		},
	}
	primary, _ := NewEngineWithDefaults().Match(asset)
	if primary.Vendor != "Synology" {
		t.Fatalf("vendor = %q, want Synology", primary.Vendor)
	}
}

func TestAppleHostDetection(t *testing.T) {
	cases := []struct {
		name      string
		txt       []string
		wantVend  string
		wantProd  string
	}{
		{"macbook", []string{"model=MacBookPro18,1", "deviceid=BC:D0:74:5D:A7:FA"}, "Apple", "Mac (AirPlay)"},
		{"iphone", []string{"model=iPhone14,2"}, "Apple", "iPhone (AirPlay)"},
		{"ipad", []string{"model=iPad13,1"}, "Apple", "iPad (AirPlay)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			asset := AssetView{
				Hostname: c.name + ".local",
				Services: []ServiceView{{Type: "airplay", Target: c.name + ".local", TXT: c.txt}},
			}
			primary, _ := NewEngineWithDefaults().Match(asset)
			if primary.Vendor != c.wantVend || primary.Product != c.wantProd {
				t.Fatalf("got %s/%s, want %s/%s", primary.Vendor, primary.Product, c.wantVend, c.wantProd)
			}
		})
	}
}

func TestChromecastDetection(t *testing.T) {
	asset := AssetView{
		Hostname: "tv.local",
		Services: []ServiceView{{Type: "googlecast", Target: "tv.local"}},
	}
	p, _ := NewEngineWithDefaults().Match(asset)
	if p.Vendor != "Google" || p.Category != CategoryMediaCast {
		t.Fatalf("got %+v", p)
	}
}

func TestPriority_QNAPBeatsAFP(t *testing.T) {
	// 同时命中 QNAP（100）和 AFP（40），主指纹必须是 QNAP。
	asset := AssetView{
		Hostname: "nas.local",
		Services: []ServiceView{
			{Type: "qdiscover", Target: "nas.local"},
			{Type: "afpovertcp", Target: "nas.local"},
		},
	}
	p, hits := NewEngineWithDefaults().Match(asset)
	if p.Vendor != "QNAP" {
		t.Fatalf("primary should be QNAP, got %q (hits=%d)", p.Vendor, len(hits))
	}
}

func TestUnknownReturnsCategoryUnknown(t *testing.T) {
	asset := AssetView{
		Hostname: "mystery.local",
		Services: []ServiceView{{Type: "unknown-service", Target: "mystery.local"}},
	}
	p, hits := NewEngineWithDefaults().Match(asset)
	if p.Category != CategoryUnknown {
		t.Fatalf("category = %q, want unknown", p.Category)
	}
	if len(hits) != 0 {
		t.Fatalf("expected no hits, got %d", len(hits))
	}
}

func TestCustomRuleInjection(t *testing.T) {
	// 团队应能在不修改本包代码的情况下注入业务自定义规则。
	eng := NewEngineWithDefaults()
	eng.AddRules(Rule{
		ID: "custom.acme", Vendor: "Acme", Product: "Acme Camera",
		Category: CategorySmartHome, Priority: 200,
		ServiceType: "http", TXTContains: []string{"vendor=acme"},
	})
	asset := AssetView{
		Hostname: "cam01.local",
		Services: []ServiceView{
			{Type: "http", Target: "cam01.local", TXT: []string{"vendor=acme", "model=AC-200"}},
		},
	}
	p, _ := eng.Match(asset)
	if p.Vendor != "Acme" || p.Product != "Acme Camera" {
		t.Fatalf("custom rule not applied: got %+v", p)
	}
}
