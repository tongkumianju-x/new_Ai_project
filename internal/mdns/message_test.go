package mdns

import (
	"net"
	"testing"
)

// TestBuildAndParseQuery: 自洽往返测试，确保我们的编解码器对得上 RFC 1035。
func TestBuildAndParseQuery(t *testing.T) {
	pkt, err := BuildQuery([]string{"_workstation._tcp.local", "_http._tcp.local"}, TypePTR, true)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	msg, err := Parse(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msg.Header.QDCount != 2 {
		t.Fatalf("QDCount = %d, want 2", msg.Header.QDCount)
	}
	if msg.Questions[0].Name != "_workstation._tcp.local" {
		t.Fatalf("q0 name = %q", msg.Questions[0].Name)
	}
	if msg.Questions[0].Type != TypePTR {
		t.Fatalf("q0 type = %d", msg.Questions[0].Type)
	}
	if msg.Questions[0].Class&0x8000 == 0 {
		t.Fatalf("unicast bit not set")
	}
}

// TestParseSyntheticResponse: 手工构造一个含 PTR/SRV/TXT/A/AAAA 的响应，
// 验证全字段解析。
func TestParseSyntheticResponse(t *testing.T) {
	// 我们用 builder 帮助函数生成一个完整响应包
	pkt := buildSyntheticResponse(t)
	msg, err := Parse(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msg.Header.ANCount == 0 {
		t.Fatalf("no answers parsed")
	}
	var sawA, sawAAAA, sawSRV, sawTXT, sawPTR bool
	for _, rr := range msg.AllRecords() {
		switch rr.Type {
		case TypeA:
			sawA = true
			if !rr.IP.Equal(net.IPv4(192, 168, 1, 10)) {
				t.Fatalf("A IP = %v", rr.IP)
			}
		case TypeAAAA:
			sawAAAA = true
			if rr.IP == nil || rr.IP.To16() == nil {
				t.Fatalf("AAAA IP = %v", rr.IP)
			}
		case TypeSRV:
			sawSRV = true
			if rr.Port != 5000 {
				t.Fatalf("SRV port = %d", rr.Port)
			}
			if rr.Target != "slw-nas.local" {
				t.Fatalf("SRV target = %q", rr.Target)
			}
		case TypeTXT:
			sawTXT = true
			if len(rr.TXT) < 1 {
				t.Fatalf("TXT empty")
			}
		case TypePTR:
			sawPTR = true
		}
	}
	if !(sawA && sawAAAA && sawSRV && sawTXT && sawPTR) {
		t.Fatalf("missing record types: A=%v AAAA=%v SRV=%v TXT=%v PTR=%v", sawA, sawAAAA, sawSRV, sawTXT, sawPTR)
	}
}
