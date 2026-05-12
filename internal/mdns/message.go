// Package mdns 实现轻量级 mDNS（RFC 6762）协议的报文构造与解析。
//
// 我们故意不依赖 miekg/dns 这类库，目的是：
//  1. 让团队理解 DNS 二进制协议的细节（Header / Question / RR / Name 压缩）；
//  2. 仅实现 mDNS 资产测绘需要的部分，体积更小、可控性更强；
//  3. 便于在后续阶段中加入对 mDNS 特有字段（如 Cache-Flush bit）的处理。
//
// 报文整体结构（参考 RFC 1035）：
//
//	+---------------------+
//	|        Header       |  12 字节
//	+---------------------+
//	|       Question      |  Name + QType(2) + QClass(2)
//	+---------------------+
//	|        Answer       |  Name + Type(2) + Class(2) + TTL(4) + RDLength(2) + RData
//	+---------------------+
//	|       Authority     |
//	+---------------------+
//	|      Additional     |
//	+---------------------+
package mdns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// DNS 资源类型
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypePTR   uint16 = 12
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeANY   uint16 = 255
)

// 类
const (
	ClassIN    uint16 = 1
	ClassFlush uint16 = 0x8000 // mDNS Cache-Flush bit
)

// Header DNS 报文头
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Question 问题段
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ResourceRecord 资源记录（统一表示）
type ResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RData    []byte
	// 已解码字段（按类型填充）
	Target   string   // CNAME/PTR/SRV target
	IP       net.IP   // A/AAAA
	Port     uint16   // SRV
	Priority uint16   // SRV
	Weight   uint16   // SRV
	TXT      []string // TXT 多串
}

// Message 整条 DNS 报文
type Message struct {
	Header     Header
	Questions  []Question
	Answers    []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
}

// AllRecords 合并三个区段，便于上层遍历。
func (m *Message) AllRecords() []ResourceRecord {
	out := make([]ResourceRecord, 0, len(m.Answers)+len(m.Authority)+len(m.Additional))
	out = append(out, m.Answers...)
	out = append(out, m.Authority...)
	out = append(out, m.Additional...)
	return out
}

// ============================================================
//                          编码部分
// ============================================================

// BuildQuery 构造一个 mDNS 单播查询报文。
//
// mDNS 标准的标记位差异：
//   - QR=0（query）
//   - 一般查询 ID=0（mDNS 不强制使用 ID 关联）
//   - Class 高位（0x8000）在 query 中复用为 "unicast-response requested"
//
// 我们对每个 service 名构造一条 PTR 查询。
func BuildQuery(serviceNames []string, qtype uint16, unicastResp bool) ([]byte, error) {
	hdr := Header{
		ID:      0,
		Flags:   0, // standard query, RD=0 (mDNS 不需递归)
		QDCount: uint16(len(serviceNames)),
	}
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], hdr.ID)
	binary.BigEndian.PutUint16(buf[2:4], hdr.Flags)
	binary.BigEndian.PutUint16(buf[4:6], hdr.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], 0)
	binary.BigEndian.PutUint16(buf[8:10], 0)
	binary.BigEndian.PutUint16(buf[10:12], 0)

	for _, name := range serviceNames {
		nb, err := encodeName(name)
		if err != nil {
			return nil, err
		}
		buf = append(buf, nb...)
		var class uint16 = ClassIN
		if unicastResp {
			class |= 0x8000
		}
		tail := make([]byte, 4)
		binary.BigEndian.PutUint16(tail[0:2], qtype)
		binary.BigEndian.PutUint16(tail[2:4], class)
		buf = append(buf, tail...)
	}
	return buf, nil
}

// encodeName 将 "name.local" 编码为 DNS 名称（不使用压缩）。
func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label %q", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0)
	return out, nil
}

// ============================================================
//                          解码部分
// ============================================================

// Parse 解析任意 DNS 报文（包括 mDNS 响应）。
// 严格按字节解析，并处理 Name Compression（指针 0xC0xx）。
func Parse(buf []byte) (*Message, error) {
	if len(buf) < 12 {
		return nil, fmt.Errorf("packet too short: %d", len(buf))
	}
	msg := &Message{
		Header: Header{
			ID:      binary.BigEndian.Uint16(buf[0:2]),
			Flags:   binary.BigEndian.Uint16(buf[2:4]),
			QDCount: binary.BigEndian.Uint16(buf[4:6]),
			ANCount: binary.BigEndian.Uint16(buf[6:8]),
			NSCount: binary.BigEndian.Uint16(buf[8:10]),
			ARCount: binary.BigEndian.Uint16(buf[10:12]),
		},
	}
	off := 12
	var err error
	for i := 0; i < int(msg.Header.QDCount); i++ {
		var q Question
		q.Name, off, err = decodeName(buf, off)
		if err != nil {
			return nil, fmt.Errorf("question[%d] name: %w", i, err)
		}
		if off+4 > len(buf) {
			return nil, fmt.Errorf("question[%d] truncated", i)
		}
		q.Type = binary.BigEndian.Uint16(buf[off : off+2])
		q.Class = binary.BigEndian.Uint16(buf[off+2 : off+4])
		off += 4
		msg.Questions = append(msg.Questions, q)
	}

	parseRRs := func(count uint16, dst *[]ResourceRecord) error {
		for i := 0; i < int(count); i++ {
			rr, newOff, err := decodeRR(buf, off)
			if err != nil {
				return err
			}
			off = newOff
			*dst = append(*dst, rr)
		}
		return nil
	}
	if err := parseRRs(msg.Header.ANCount, &msg.Answers); err != nil {
		return nil, fmt.Errorf("answers: %w", err)
	}
	if err := parseRRs(msg.Header.NSCount, &msg.Authority); err != nil {
		return nil, fmt.Errorf("authority: %w", err)
	}
	if err := parseRRs(msg.Header.ARCount, &msg.Additional); err != nil {
		return nil, fmt.Errorf("additional: %w", err)
	}
	return msg, nil
}

func decodeRR(buf []byte, off int) (ResourceRecord, int, error) {
	var rr ResourceRecord
	var err error
	rr.Name, off, err = decodeName(buf, off)
	if err != nil {
		return rr, off, fmt.Errorf("rr name: %w", err)
	}
	if off+10 > len(buf) {
		return rr, off, fmt.Errorf("rr header truncated")
	}
	rr.Type = binary.BigEndian.Uint16(buf[off : off+2])
	rr.Class = binary.BigEndian.Uint16(buf[off+2 : off+4])
	rr.TTL = binary.BigEndian.Uint32(buf[off+4 : off+8])
	rdLen := binary.BigEndian.Uint16(buf[off+8 : off+10])
	off += 10
	if off+int(rdLen) > len(buf) {
		return rr, off, fmt.Errorf("rdata truncated")
	}
	rr.RData = buf[off : off+int(rdLen)]

	switch rr.Type {
	case TypeA:
		if rdLen == 4 {
			rr.IP = net.IP(append([]byte{}, rr.RData...))
		}
	case TypeAAAA:
		if rdLen == 16 {
			rr.IP = net.IP(append([]byte{}, rr.RData...))
		}
	case TypePTR, TypeCNAME:
		target, _, err := decodeName(buf, off)
		if err == nil {
			rr.Target = target
		}
	case TypeSRV:
		if rdLen >= 6 {
			rr.Priority = binary.BigEndian.Uint16(rr.RData[0:2])
			rr.Weight = binary.BigEndian.Uint16(rr.RData[2:4])
			rr.Port = binary.BigEndian.Uint16(rr.RData[4:6])
			target, _, err := decodeName(buf, off+6)
			if err == nil {
				rr.Target = target
			}
		}
	case TypeTXT:
		// TXT 由若干 <length-prefixed string> 组成
		i := 0
		for i < int(rdLen) {
			l := int(rr.RData[i])
			i++
			if i+l > int(rdLen) {
				break
			}
			rr.TXT = append(rr.TXT, string(rr.RData[i:i+l]))
			i += l
		}
	}
	off += int(rdLen)
	return rr, off, nil
}

// decodeName 解析 DNS 名称字段（含压缩指针）。
// 返回 (name, nextOffset, error)。nextOffset 指向 name 字段之后的位置；
// 即使遇到压缩指针，nextOffset 也只前进 2 字节。
func decodeName(buf []byte, off int) (string, int, error) {
	var labels []string
	original := off
	jumped := false
	hops := 0
	const maxHops = 10
	for {
		if off >= len(buf) {
			return "", original, fmt.Errorf("name overflow")
		}
		l := buf[off]
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			// 压缩指针
			if off+1 >= len(buf) {
				return "", original, fmt.Errorf("compression overflow")
			}
			ptr := int(binary.BigEndian.Uint16(buf[off:off+2]) & 0x3FFF)
			if !jumped {
				original = off + 2
			}
			off = ptr
			jumped = true
			hops++
			if hops > maxHops {
				return "", original, fmt.Errorf("compression loop")
			}
			continue
		}
		off++
		if off+int(l) > len(buf) {
			return "", original, fmt.Errorf("label overflow")
		}
		labels = append(labels, string(buf[off:off+int(l)]))
		off += int(l)
	}
	if !jumped {
		original = off
	}
	return strings.Join(labels, "."), original, nil
}
