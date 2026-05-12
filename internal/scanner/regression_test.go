package scanner_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/newAIProject/mdns-scanner/internal/mdns"
	"github.com/newAIProject/mdns-scanner/internal/output"
	"github.com/newAIProject/mdns-scanner/internal/scanner"
)

// TestRegression_NoMetaServicesInAnswers
//
// 真实运行（mdnsscan --cidr 127.0.0.1/32）时观察到 answers 段意外包含了
// "_services._dns-sd._udp.local" 这条 DNS-SD 元枚举答案。
// 它不属于业务资产，会污染对外报告。
//
// 修复后必须保证：answers.PTR 不包含任何 "_services." 开头的条目。
func TestRegression_NoMetaServicesInAnswers(t *testing.T) {
	pkt := buildPktWithMetaPTR(t)
	msg, err := mdns.Parse(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assets := scanner.MergeMessages(net.ParseIP("127.0.0.1"), []*mdns.Message{msg})
	if len(assets) == 0 {
		t.Fatal("no asset")
	}
	for _, p := range assets[0].PTRAnswers {
		if strings.HasPrefix(p, "_services.") {
			t.Fatalf("PTRAnswers leaked meta entry: %q (full=%v)", p, assets[0].PTRAnswers)
		}
	}
	// 真实业务 PTR 必须保留
	if !containsString(assets[0].PTRAnswers, "_airplay._tcp.local") {
		t.Fatalf("expected _airplay._tcp.local in PTRAnswers, got %v", assets[0].PTRAnswers)
	}

	// 输出文本里也不能出现 "_services."
	var buf bytes.Buffer
	if err := output.WriteText(&buf, assets); err != nil {
		t.Fatalf("write text: %v", err)
	}
	if strings.Contains(buf.String(), "_services.") {
		t.Fatalf("text output leaked meta PTR\n%s", buf.String())
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// 构造含 _services 元 PTR + 一条真实 _airplay PTR 的报文
func buildPktWithMetaPTR(t *testing.T) []byte {
	t.Helper()

	encName := func(name string) []byte {
		out := []byte{}
		for _, lab := range strings.Split(strings.TrimSuffix(name, "."), ".") {
			out = append(out, byte(len(lab)))
			out = append(out, []byte(lab)...)
		}
		return append(out, 0)
	}
	addRR := func(buf *[]byte, n *uint16, name string, typ, class uint16, ttl uint32, rd []byte) {
		*buf = append(*buf, encName(name)...)
		h := make([]byte, 10)
		binary.BigEndian.PutUint16(h[0:2], typ)
		binary.BigEndian.PutUint16(h[2:4], class)
		binary.BigEndian.PutUint32(h[4:8], ttl)
		binary.BigEndian.PutUint16(h[8:10], uint16(len(rd)))
		*buf = append(*buf, h...)
		*buf = append(*buf, rd...)
		*n++
	}

	var body []byte
	var cnt uint16
	// 元 PTR — 不应出现在 answers
	addRR(&body, &cnt, "_services._dns-sd._udp.local", mdns.TypePTR, mdns.ClassIN, 10,
		encName("_airplay._tcp.local"))
	// 真实 PTR
	addRR(&body, &cnt, "_airplay._tcp.local", mdns.TypePTR, mdns.ClassIN, 10,
		encName("MyMac._airplay._tcp.local"))
	// SRV
	target := encName("mymac.local")
	rd := make([]byte, 6+len(target))
	binary.BigEndian.PutUint16(rd[4:6], 7000)
	copy(rd[6:], target)
	addRR(&body, &cnt, "MyMac._airplay._tcp.local", mdns.TypeSRV, mdns.ClassIN, 10, rd)
	// A
	addRR(&body, &cnt, "mymac.local", mdns.TypeA, mdns.ClassIN, 10, net.IPv4(127, 0, 0, 1).To4())

	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8400)
	binary.BigEndian.PutUint16(hdr[6:8], cnt)
	return append(hdr, body...)
}
