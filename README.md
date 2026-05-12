# mdnsscan — mDNS 网站测绘 CLI

> 一个面向团队代码质量提升的教学型项目：用纯 Go 标准库实现 mDNS 协议，
> 完成"输入 IP 网段 + 端口范围 → 输出资产 + 深度 banner"的网络资产测绘能力。

## 1. 能力概览

- 输入：CIDR 网段（如 `192.168.1.0/24`）+ 端口范围（`5353,80,443,5000`）
- 输出：每台资产的服务清单（service / port / transport / Name / IPv4 / IPv6 / Hostname / TTL / 深度 banner）
- 深度识别字段：解析 mDNS 的 `PTR / SRV / TXT / A / AAAA` 记录，TXT 中的 key=value 直接展示为 banner
- 两种输出格式：`text`（与示例对齐）/ `json`（供下游消费）
- 两种探测模式：单播探测网段所有 IP（默认）/ 组播探测本地 LAN（`--multicast`）

## 2. 工程结构

```
.
├── cmd/
│   ├── mdnsscan/        # 主 CLI 入口
│   └── mdnsreplay/      # 离线回放工具：用合成数据集验证整条链路
├── internal/
│   ├── mdns/            # mDNS 协议编解码（不依赖第三方 DNS 库）
│   ├── scanner/         # 扫描调度 + 资产聚合
│   └── output/          # 文本/JSON 格式化
├── pkg/
│   └── iprange/         # CIDR 与端口范围解析（公共能力）
└── docs/
```

## 3. 快速开始

```bash
# 编译
go build ./cmd/mdnsscan
go build ./cmd/mdnsreplay

# 1) 用合成数据集回放（无需联网，用于 CI / 验收 banner 深度）
./mdnsreplay

# 2) 真实扫描指定网段（需要 UDP 5353 出网）
./mdnsscan --cidr 192.168.1.0/24 --ports 5353,80,443,5000,548 --verbose

# 3) JSON 输出
./mdnsscan --cidr 192.168.1.0/24 --output json --out-file assets.json

# 4) 仅做本地组播探测
./mdnsscan --multicast-only --verbose
```

## 4. 验收：与题目示例对齐的输出

执行 `./mdnsreplay` 得到：

```
services:
  9/tcp workstation:
    Name=slw-nas [24:5e:be:69:a3:13]
    IPv4=192.168.1.10
    IPv6=fe80::265e:beff:fe69:a313
    Hostname=slw-nas.local
    TTL=10
  5000/tcp http:
    Name=slw-nas
    IPv4=192.168.1.10
    IPv6=fe80::265e:beff:fe69:a313
    Hostname=slw-nas.local
    TTL=10
    path=/
  445/tcp smb:
    ...
  5000/tcp qdiscover:
    ...
    accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
  device-info:
    Name=slw-nas(AFP)
    ...
    model=Xserve
  548/tcp afpovertcp:
    ...
answers:
  PTR:
    _workstation._tcp.local
    _http._tcp.local
    _smb._tcp.local
    _qdiscover._tcp.local
    _device-info._tcp.local
    _afpovertcp._tcp.local
```

## 5. 给团队的代码质量要点（资深开发者视角）

1. **协议自实现**：刻意不依赖 `miekg/dns` 等大库，让团队理解 DNS 二进制协议（Header / Name 压缩 / RR）。
2. **包内职责单一**：`mdns` 只管协议，`scanner` 只管调度，`output` 只管格式化。任何一层都能独立测试。
3. **可测试性优先**：`MergeMessages` 公开导出便于离线/合成数据回放；新增 `cmd/mdnsreplay` 解决"无实网环境也能验收"。
4. **错误尽早返回**：CLI / 扫描器 / 解析器三层都遵循"出错即停 + 上下文包装"。
5. **资源/上下文显式管理**：每个 UDP 连接 `defer Close()`；扫描接受 `context.Context`，支持 `Ctrl-C` 取消。
6. **零拷贝/低分配**：CIDR 用迭代器逐个产 IP，避免 `/16` 网段一次性分配。
7. **文档即合约**：每个文件首部注释说明该包的设计取舍，方便新人接手。

## 6. 后续递进路线（按分支逐步推进）

- [x] feature/mdns-scanner-init — 基础工程 + 协议 + 单播扫描 + 测试 ✅ 已合并 main
- [x] feature/mdns-fingerprint — **本分支** 厂商指纹库（QNAP/Synology/Apple/Chromecast/HomeKit/Printer 等）+ 自定义规则注入 ✅ 测试通过
- [ ] feature/mdns-multicast-iface — 增强组播：按 `--iface` 选网卡，单播失败时自动回退
- [ ] feature/mdns-rate-limit — 大网段并发限流 + 重试 + 抖动
- [ ] feature/mdns-output-csv-prom — CSV / Prometheus 指标输出
- [ ] feature/mdns-e2e — 起本地 mDNS mock 做集成测试

## 7. 测试

```bash
go test ./... -v
```

当前覆盖：
- `internal/mdns`：编解码往返 + 多记录类型（A/AAAA/SRV/TXT/PTR）合成报文解析
- `internal/scanner`：端到端 banner 深度断言，覆盖 6 种典型 mDNS 服务
- `internal/fingerprint`：QNAP/Synology/Apple/Chromecast 单元测试 + 优先级 + 自定义规则 + 端到端集成
- `pkg/iprange`：端口表达式 + CIDR 迭代

