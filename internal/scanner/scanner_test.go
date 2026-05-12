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

// TestMergeMessages_BannerDepth：用合成的 mDNS 响应跑一遍合并 + 输出，
// 校验输出里包含示例所要求的所有关键字段：Name/IPv4/IPv6/Hostname/TTL/TXT 键值对。
func TestMergeMessages_BannerDepth(t *testing.T) {
	pkt := buildQNAPLikeResponse(t)
	msg, err := mdns.Parse(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assets := scanner.MergeMessages(net.ParseIP("192.168.1.10"), []*mdns.Message{msg})
	if len(assets) == 0 {
		t.Fatal("no assets")
	}
	a := assets[0]
	if a.Hostname != "slw-nas.local" {
		t.Fatalf("hostname = %q", a.Hostname)
	}
	if a.IPv4.String() != "192.168.1.10" {
		t.Fatalf("ipv4 = %v", a.IPv4)
	}
	if a.IPv6 == nil {
		t.Fatalf("ipv6 missing")
	}

	var buf bytes.Buffer
	if err := output.WriteText(&buf, assets); err != nil {
		t.Fatalf("write text: %v", err)
	}
	out := buf.String()

	// 校验示例中要求的字段都出现了
	mustContain := []string{
		"services:",
		"Name=slw-nas",
		"IPv4=192.168.1.10",
		"IPv6=fe80::265e:beff:fe69:a313",
		"Hostname=slw-nas.local",
		"TTL=10",
		// 服务节点（端口 + transport + 服务名）
		"5000/tcp http",
		"445/tcp smb",
		"548/tcp afpovertcp",
		// 深度 banner 信息（TXT）
		"path=/",
		"model=TS-X64",
		"answers:",
		"PTR:",
		"_http._tcp.local",
		"_smb._tcp.local",
		"_afpovertcp._tcp.local",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\nFULL OUTPUT:\n%s", s, out)
		}
	}
}

// buildQNAPLikeResponse 构造一个模拟 QNAP NAS 的 mDNS 响应：
//   - 多服务（http/smb/afpovertcp/qdiscover/device-info）
//   - 完整的 PTR/SRV/TXT/A/AAAA 链路
func buildQNAPLikeResponse(t *testing.T) []byte {
	t.Helper()
	w := newRespWriter()

	// answers: 5 个 PTR
	w.appendPTR("_http._tcp.local", "slw-nas._http._tcp.local")
	w.appendPTR("_smb._tcp.local", "slw-nas._smb._tcp.local")
	w.appendPTR("_qdiscover._tcp.local", "slw-nas._qdiscover._tcp.local")
	w.appendPTR("_device-info._tcp.local", "slw-nas(AFP)._device-info._tcp.local")
	w.appendPTR("_afpovertcp._tcp.local", "slw-nas(AFP)._afpovertcp._tcp.local")

	// SRV: 各服务的端口
	w.appendSRV("slw-nas._http._tcp.local", 5000, "slw-nas.local")
	w.appendSRV("slw-nas._smb._tcp.local", 445, "slw-nas.local")
	w.appendSRV("slw-nas._qdiscover._tcp.local", 5000, "slw-nas.local")
	w.appendSRV("slw-nas(AFP)._afpovertcp._tcp.local", 548, "slw-nas.local")

	// TXT: 深度 banner
	w.appendTXT("slw-nas._http._tcp.local", []string{"path=/"})
	w.appendTXT("slw-nas._qdiscover._tcp.local", []string{
		"accessType=https", "accessPort=86", "model=TS-X64",
		"displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214",
	})
	w.appendTXT("slw-nas(AFP)._device-info._tcp.local", []string{"model=Xserve"})

	// A / AAAA
	w.appendA("slw-nas.local", net.IPv4(192, 168, 1, 10))
	w.appendAAAA("slw-nas.local", net.ParseIP("fe80::265e:beff:fe69:a313"))

	return w.bytes()
}

// --- 极简 builder（仅测试用） ---

type respWriter struct {
	an  []byte
	cnt uint16
}

func newRespWriter() *respWriter { return &respWriter{} }

func encName(name string) []byte {
	out := []byte{}
	for _, lab := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		out = append(out, byte(len(lab)))
		out = append(out, []byte(lab)...)
	}
	out = append(out, 0)
	return out
}

func (w *respWriter) addRR(name string, typ, class uint16, ttl uint32, rdata []byte) {
	w.an = append(w.an, encName(name)...)
	hdr := make([]byte, 10)
	binary.BigEndian.PutUint16(hdr[0:2], typ)
	binary.BigEndian.PutUint16(hdr[2:4], class)
	binary.BigEndian.PutUint32(hdr[4:8], ttl)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(rdata)))
	w.an = append(w.an, hdr...)
	w.an = append(w.an, rdata...)
	w.cnt++
}

func (w *respWriter) appendPTR(name, target string) {
	w.addRR(name, mdns.TypePTR, mdns.ClassIN, 10, encName(target))
}

func (w *respWriter) appendSRV(name string, port uint16, target string) {
	tgt := encName(target)
	rdata := make([]byte, 6+len(tgt))
	binary.BigEndian.PutUint16(rdata[0:2], 0)
	binary.BigEndian.PutUint16(rdata[2:4], 0)
	binary.BigEndian.PutUint16(rdata[4:6], port)
	copy(rdata[6:], tgt)
	w.addRR(name, mdns.TypeSRV, mdns.ClassIN, 10, rdata)
}

func (w *respWriter) appendTXT(name string, kvs []string) {
	rdata := []byte{}
	for _, s := range kvs {
		rdata = append(rdata, byte(len(s)))
		rdata = append(rdata, []byte(s)...)
	}
	w.addRR(name, mdns.TypeTXT, mdns.ClassIN, 10, rdata)
}

func (w *respWriter) appendA(name string, ip net.IP) {
	w.addRR(name, mdns.TypeA, mdns.ClassIN, 10, ip.To4())
}

func (w *respWriter) appendAAAA(name string, ip net.IP) {
	w.addRR(name, mdns.TypeAAAA, mdns.ClassIN, 10, ip.To16())
}

func (w *respWriter) bytes() []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8400)
	binary.BigEndian.PutUint16(hdr[4:6], 0)
	binary.BigEndian.PutUint16(hdr[6:8], w.cnt)
	binary.BigEndian.PutUint16(hdr[8:10], 0)
	binary.BigEndian.PutUint16(hdr[10:12], 0)
	return append(hdr, w.an...)
}
