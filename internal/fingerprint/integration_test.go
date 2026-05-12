package fingerprint_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/newAIProject/mdns-scanner/internal/fingerprint"
	"github.com/newAIProject/mdns-scanner/internal/mdns"
	"github.com/newAIProject/mdns-scanner/internal/output"
	"github.com/newAIProject/mdns-scanner/internal/scanner"
)

// TestFingerprint_EndToEnd: 协议解析 → 资产合并 → 指纹识别 → 输出 全链路。
//
// 验收条件（用户要求）：
//   1. 主指纹 vendor=QNAP, category=nas
//   2. text 输出第一行包含 "fingerprint: vendor=QNAP product=QNAP NAS category=nas"
//   3. tags 至少包含 qnap.qdiscover
//   4. 多规则同时命中时按 Priority 取最高
func TestFingerprint_EndToEnd(t *testing.T) {
	pkt := buildQNAPPacket()
	msg, err := mdns.Parse(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assets := scanner.MergeMessages(net.ParseIP("192.168.1.10"), []*mdns.Message{msg})
	if len(assets) == 0 {
		t.Fatal("no asset")
	}

	// 应用指纹
	eng := fingerprint.NewEngineWithDefaults()
	for _, a := range assets {
		view := fingerprint.AssetView{Hostname: a.GetHostname()}
		for _, s := range a.ServiceSnapshot() {
			view.Services = append(view.Services, fingerprint.ServiceView{
				Type: s.Type, Transport: s.Transport, Target: s.Target, TXT: s.TXT,
			})
		}
		p, hits := eng.Match(view)
		var tags []string
		for _, h := range hits {
			tags = append(tags, h.RuleID)
		}
		a.SetFingerprint(p.Vendor, p.Product, string(p.Category), tags)
	}

	a := assets[0]
	if a.Vendor != "QNAP" {
		t.Fatalf("vendor = %q, want QNAP", a.Vendor)
	}
	if a.Category != "nas" {
		t.Fatalf("category = %q, want nas", a.Category)
	}
	if !containsTag(a.Tags, "qnap.qdiscover") {
		t.Fatalf("tags = %v, want contain qnap.qdiscover", a.Tags)
	}

	// 渲染 text，校验关键文字
	var buf bytes.Buffer
	if err := output.WriteText(&buf, assets); err != nil {
		t.Fatalf("write text: %v", err)
	}
	out := buf.String()
	mustContain := []string{
		"fingerprint: vendor=QNAP",
		"category=nas",
		"tags:",
		"qnap.qdiscover",
		// 原有断言不应该回归
		"5000/tcp qdiscover",
		"model=TS-X64",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\n--- FULL ---\n%s", s, out)
		}
	}
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// --- 报文构造工具（与 scanner_test 保持一致风格） ---

func encName(name string) []byte {
	out := []byte{}
	for _, lab := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		out = append(out, byte(len(lab)))
		out = append(out, []byte(lab)...)
	}
	return append(out, 0)
}

type wr struct {
	b []byte
	n uint16
}

func (w *wr) addRR(name string, t, c uint16, ttl uint32, rd []byte) {
	w.b = append(w.b, encName(name)...)
	h := make([]byte, 10)
	binary.BigEndian.PutUint16(h[0:2], t)
	binary.BigEndian.PutUint16(h[2:4], c)
	binary.BigEndian.PutUint32(h[4:8], ttl)
	binary.BigEndian.PutUint16(h[8:10], uint16(len(rd)))
	w.b = append(w.b, h...)
	w.b = append(w.b, rd...)
	w.n++
}

func buildQNAPPacket() []byte {
	w := &wr{}
	w.addRR("_qdiscover._tcp.local", mdns.TypePTR, mdns.ClassIN, 10, encName("slw-nas._qdiscover._tcp.local"))
	w.addRR("_http._tcp.local", mdns.TypePTR, mdns.ClassIN, 10, encName("slw-nas._http._tcp.local"))
	w.addRR("_smb._tcp.local", mdns.TypePTR, mdns.ClassIN, 10, encName("slw-nas._smb._tcp.local"))
	w.addRR("_afpovertcp._tcp.local", mdns.TypePTR, mdns.ClassIN, 10, encName("slw-nas._afpovertcp._tcp.local"))

	srv := func(name string, port uint16, target string) {
		t := encName(target)
		rd := make([]byte, 6+len(t))
		binary.BigEndian.PutUint16(rd[4:6], port)
		copy(rd[6:], t)
		w.addRR(name, mdns.TypeSRV, mdns.ClassIN, 10, rd)
	}
	srv("slw-nas._qdiscover._tcp.local", 5000, "slw-nas.local")
	srv("slw-nas._http._tcp.local", 5000, "slw-nas.local")
	srv("slw-nas._smb._tcp.local", 445, "slw-nas.local")
	srv("slw-nas._afpovertcp._tcp.local", 548, "slw-nas.local")

	txt := func(name string, kvs ...string) {
		rd := []byte{}
		for _, s := range kvs {
			rd = append(rd, byte(len(s)))
			rd = append(rd, []byte(s)...)
		}
		w.addRR(name, mdns.TypeTXT, mdns.ClassIN, 10, rd)
	}
	txt("slw-nas._qdiscover._tcp.local",
		"accessType=https", "accessPort=86", "model=TS-X64",
		"displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214")
	txt("slw-nas._http._tcp.local", "path=/")

	w.addRR("slw-nas.local", mdns.TypeA, mdns.ClassIN, 10, net.IPv4(192, 168, 1, 10).To4())
	w.addRR("slw-nas.local", mdns.TypeAAAA, mdns.ClassIN, 10, net.ParseIP("fe80::265e:beff:fe69:a313").To16())

	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8400)
	binary.BigEndian.PutUint16(hdr[6:8], w.n)
	return append(hdr, w.b...)
}
