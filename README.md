# mdns-mapper

`mdns-mapper` 是一个使用 Go 编写的 mDNS/DNS-SD 网站测绘 CLI 工具。它接收
IP 网段和端口范围作为输入，发现局域网内通过 mDNS 暴露的服务资产，并输出
`ip`、`port`、`host` 以及由 mDNS 记录组装出的深度识别 banner。

该工具通过标准 mDNS 组播查询发现服务类型、服务实例、端口、主机名、IPv4、
IPv6 和 TXT 元数据，适合用于局域网资产识别和 mDNS 服务盘点。

## 功能

- 支持通过 CLI 输入目标 CIDR 网段。
- 支持通过 CLI 输入端口列表和端口范围，例如 `9,445,5000-5100`。
- 通过 `_services._dns-sd._udp.local` 发现 mDNS/DNS-SD 服务类型。
- 跟随服务类型 PTR 记录发现具体服务实例。
- 查询服务实例的 `SRV` 和 `TXT` 记录。
- 查询 SRV target 主机名的 `A` 和 `AAAA` 记录。
- 输出资产字段：`ip`、`port`、`host`、`Name`、`IPv4`、`IPv6`、`Hostname`、
  `TTL` 和 TXT banner。
- 保留 TXT 记录原始顺序，避免破坏厂商 banner 语义，例如
  `accessType=https,accessPort=86,model=...`。
- 支持 `device-info:` 这类无端口 mDNS 元数据块。
- 支持文本输出和 JSON 输出。
- IPv4 mDNS 与 IPv6 mDNS 独立探测，某一协议不可用时不会阻断另一协议结果。

## 构建

```bash
go build ./...
```

## 使用

```bash
go run . -cidr 192.168.1.0/24 -ports 1-65535 -timeout 5s
```

常用参数：

```text
-cidr      目标 IP 网段，例如 192.168.1.0/24
-ports     端口列表或端口范围，例如 9,445,5000-5100
-timeout   mDNS 发现超时时间，默认 5s
-json      使用 JSON 格式输出
```

JSON 输出示例：

```bash
go run . -cidr 192.168.1.0/24 -ports 9,445,5000-5100 -json
```

## 输出格式

默认文本输出结构如下：

```text
services:
<port>/<proto> <service>:
Name=<服务实例名>
IPv4=<匹配到的 IPv4>
IPv6=<匹配到的 IPv6>
Hostname=<服务目标主机名>
TTL=<记录 TTL>
<由 TXT 记录拼接出的 banner>
answers:
PTR:
<服务类型 PTR>
```

`device-info` 这类没有端口的元数据服务会输出为：

```text
device-info:
Name=<服务实例名>
IPv4=<匹配到的 IPv4>
IPv6=<匹配到的 IPv6>
Hostname=<推断或匹配到的主机名>
TTL=<记录 TTL>
<TXT banner>
```

文本输出示例：

```text
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
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
device-info:
Name=slw-nas(AFP)
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
model=Xserve
answers:
PTR:
_workstation._tcp.local
_http._tcp.local
_qdiscover._tcp.local
_device-info._tcp.local
```

## 实现思路

项目不依赖第三方库，使用 Go 标准库完成 UDP 组播收发，并实现了一个轻量 DNS
解析器，只解析 mDNS 资产测绘需要的记录类型。

核心流程：

1. 向 mDNS 组播地址查询 `_services._dns-sd._udp.local` 的 PTR 记录，发现服务类型，
   例如 `_http._tcp.local`、`_smb._tcp.local`、`_qdiscover._tcp.local`。
2. 对每个服务类型继续查询 PTR，获得具体服务实例，例如
   `slw-nas._qdiscover._tcp.local`。
3. 对每个服务实例查询 `SRV` 和 `TXT`：
   - `SRV` 提供服务端口和目标主机名；
   - `TXT` 作为深度识别 banner，例如 QNAP 的型号、固件版本、访问端口等。
4. 对 SRV target 主机名查询 `A` 和 `AAAA`，获得 IPv4 和 IPv6。
5. 将 PTR、SRV、TXT、A、AAAA 记录聚合成资产。
6. 根据输入 CIDR 和端口范围过滤资产。
7. 按题目示例格式输出文本，或在 `-json` 开启时输出结构化 JSON。

IPv4 mDNS 使用 `224.0.0.251:5353`，IPv6 mDNS 使用 `ff02::fb:5353`。两者并发探测；
如果当前系统或网络不支持 IPv6 mDNS，IPv4 结果仍可正常输出。

## 资产匹配规则

- 有端口的服务必须命中用户输入的端口范围。
- 资产 IP 必须属于用户输入的 CIDR 网段。
- `device-info:` 等无端口元数据只作为已命中端口服务主机的补充信息输出；如果同一
  主机没有任何端口服务命中用户输入的端口范围，则不会单独输出。
- 无端口元数据不会借用其它主机的 IP；如果无法匹配到自身主机名对应的 `A` 或
  `AAAA` 记录，则不会通过 CIDR 过滤。
- TXT banner 会去重，但保留 mDNS 响应中的原始顺序。
- `answers: PTR:` 只输出服务类型 PTR，不混入具体服务实例名。

## 测试

运行全部测试：

```bash
go test ./...
```

当前测试覆盖：

- 端口范围解析；
- DNS 压缩名称解析；
- 示例级 mDNS 资产聚合；
- `qdiscover` 深度 TXT banner 顺序；
- `device-info:` 无端口输出；
- `answers: PTR:` 服务类型过滤；
- 多设备场景下不错误借用其它主机 IP；
- IPv4/IPv6 探测错误降级策略。

## GitHub

公开仓库地址：

```text
https://github.com/xinyuan-js/timu
```
