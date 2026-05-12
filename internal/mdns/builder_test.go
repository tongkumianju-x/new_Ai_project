package mdns

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildSyntheticResponse 构造一个内容丰富的 mDNS 响应报文，
// 模拟 QNAP NAS（slw-nas）的真实回包形态：
//   - PTR: _http._tcp.local -> slw-nas._http._tcp.local
//   - SRV: slw-nas._http._tcp.local 5000 slw-nas.local
//   - TXT: path=/
//   - A:   slw-nas.local -> 192.168.1.10
//   - AAAA: slw-nas.local -> fe80::265e:beff:fe69:a313
func buildSyntheticResponse(t *testing.T) []byte {
	t.Helper()
	var buf []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0)            // ID
	binary.BigEndian.PutUint16(hdr[2:4], 0x8400)        // QR=1, AA=1
	binary.BigEndian.PutUint16(hdr[4:6], 0)            // QDCount
	binary.BigEndian.PutUint16(hdr[6:8], 5)            // ANCount
	binary.BigEndian.PutUint16(hdr[8:10], 0)
	binary.BigEndian.PutUint16(hdr[10:12], 0)
	buf = append(buf, hdr...)

	appendName := func(b []byte, name string) []byte {
		nb, err := encodeName(name)
		if err != nil {
			t.Fatalf("encode %q: %v", name, err)
		}
		return append(b, nb...)
	}
	appendRRHeader := func(b []byte, name string, typ, class uint16, ttl uint32, rdlen uint16) []byte {
		b = appendName(b, name)
		hdr := make([]byte, 10)
		binary.BigEndian.PutUint16(hdr[0:2], typ)
		binary.BigEndian.PutUint16(hdr[2:4], class)
		binary.BigEndian.PutUint32(hdr[4:8], ttl)
		binary.BigEndian.PutUint16(hdr[8:10], rdlen)
		return append(b, hdr...)
	}

	// PTR: _http._tcp.local -> slw-nas._http._tcp.local
	{
		target, _ := encodeName("slw-nas._http._tcp.local")
		buf = appendRRHeader(buf, "_http._tcp.local", TypePTR, ClassIN, 10, uint16(len(target)))
		buf = append(buf, target...)
	}
	// SRV: slw-nas._http._tcp.local
	{
		target, _ := encodeName("slw-nas.local")
		rdata := make([]byte, 6+len(target))
		binary.BigEndian.PutUint16(rdata[0:2], 0)    // priority
		binary.BigEndian.PutUint16(rdata[2:4], 0)    // weight
		binary.BigEndian.PutUint16(rdata[4:6], 5000) // port
		copy(rdata[6:], target)
		buf = appendRRHeader(buf, "slw-nas._http._tcp.local", TypeSRV, ClassIN, 10, uint16(len(rdata)))
		buf = append(buf, rdata...)
	}
	// TXT: path=/
	{
		s := "path=/"
		rdata := append([]byte{byte(len(s))}, []byte(s)...)
		buf = appendRRHeader(buf, "slw-nas._http._tcp.local", TypeTXT, ClassIN, 10, uint16(len(rdata)))
		buf = append(buf, rdata...)
	}
	// A: slw-nas.local -> 192.168.1.10
	{
		ip := net.IPv4(192, 168, 1, 10).To4()
		buf = appendRRHeader(buf, "slw-nas.local", TypeA, ClassIN, 10, 4)
		buf = append(buf, ip...)
	}
	// AAAA: slw-nas.local -> fe80::265e:beff:fe69:a313
	{
		ip := net.ParseIP("fe80::265e:beff:fe69:a313").To16()
		buf = appendRRHeader(buf, "slw-nas.local", TypeAAAA, ClassIN, 10, 16)
		buf = append(buf, ip...)
	}
	return buf
}
