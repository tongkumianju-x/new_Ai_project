// Package output 提供资产数据的格式化能力，复刻题目所示文本格式，
// 同时支持 JSON 输出，便于与下游系统对接。
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/newAIProject/mdns-scanner/internal/scanner"
)

// WriteText 按示例的人类可读格式写出资产报告。
//
// 输出节段：
//
//	services:
//	  <port>/<transport> <type>:
//	    Name=<instance>
//	    IPv4=<ip>
//	    IPv6=<ip>
//	    Hostname=<host>
//	    TTL=<ttl>
//	    <txt key=val>...
//	answers:
//	  PTR:
//	    <serviceType>...
func WriteText(w io.Writer, assets []*scanner.Asset) error {
	for i, a := range assets {
		if i > 0 {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "----")
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, "services:")
		for _, s := range a.Services {
			head := serviceHeader(s)
			fmt.Fprintf(w, "  %s:\n", head)
			fmt.Fprintf(w, "    Name=%s\n", emptyAsDash(s.Instance))
			if a.IPv4 != nil {
				fmt.Fprintf(w, "    IPv4=%s\n", a.IPv4.String())
			}
			if a.IPv6 != nil {
				fmt.Fprintf(w, "    IPv6=%s\n", a.IPv6.String())
			}
			if a.Hostname != "" {
				host := a.Hostname
				if !strings.HasSuffix(host, ".local") {
					host = host + ".local"
				}
				fmt.Fprintf(w, "    Hostname=%s\n", host)
			}
			if s.TTL > 0 {
				fmt.Fprintf(w, "    TTL=%d\n", s.TTL)
			} else if a.TTL > 0 {
				fmt.Fprintf(w, "    TTL=%d\n", a.TTL)
			}
			if len(s.TXT) > 0 {
				// 一条 TXT 行：key=value,key=value （示例风格）
				fmt.Fprintf(w, "    %s\n", strings.Join(s.TXT, ","))
			}
		}
		fmt.Fprintln(w, "answers:")
		fmt.Fprintln(w, "  PTR:")
		for _, p := range a.PTRAnswers {
			fmt.Fprintf(w, "    %s\n", p)
		}
	}
	return nil
}

// serviceHeader 拼接 "<port>/<transport> <type>"，缺端口时退化为 "<type>"
func serviceHeader(s *scanner.Service) string {
	if s.Port > 0 && s.Transport != "" {
		return fmt.Sprintf("%d/%s %s", s.Port, s.Transport, s.Type)
	}
	return s.Type
}

func emptyAsDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// WriteJSON 输出 JSON 报告，便于下游消费。
func WriteJSON(w io.Writer, assets []*scanner.Asset) error {
	type serviceOut struct {
		Type      string   `json:"type"`
		Transport string   `json:"transport,omitempty"`
		Port      int      `json:"port"`
		Name      string   `json:"name"`
		TXT       []string `json:"txt,omitempty"`
		TTL       uint32   `json:"ttl,omitempty"`
	}
	type assetOut struct {
		Hostname   string       `json:"hostname,omitempty"`
		IPv4       string       `json:"ipv4,omitempty"`
		IPv6       string       `json:"ipv6,omitempty"`
		TTL        uint32       `json:"ttl,omitempty"`
		Services   []serviceOut `json:"services"`
		PTRAnswers []string     `json:"ptr_answers,omitempty"`
	}
	out := make([]assetOut, 0, len(assets))
	for _, a := range assets {
		ao := assetOut{
			Hostname:   a.Hostname,
			TTL:        a.TTL,
			PTRAnswers: a.PTRAnswers,
		}
		if a.IPv4 != nil {
			ao.IPv4 = a.IPv4.String()
		}
		if a.IPv6 != nil {
			ao.IPv6 = a.IPv6.String()
		}
		for _, s := range a.Services {
			ao.Services = append(ao.Services, serviceOut{
				Type:      s.Type,
				Transport: s.Transport,
				Port:      s.Port,
				Name:      s.Instance,
				TXT:       s.TXT,
				TTL:       s.TTL,
			})
		}
		out = append(out, ao)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
