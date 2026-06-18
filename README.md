# mdns-mapper

`mdns-mapper` is a Go CLI for discovering mDNS assets in an IP CIDR and port range.

It sends standard mDNS multicast PTR queries, follows discovered service types, and prints
matched assets with `ip`, `port`, `host`, and a deeper banner assembled from mDNS records
(`Name`, `IPv4`, `IPv6`, `Hostname`, `TTL`, and TXT key/value data).

## Build

```bash
go build ./...
```

## Usage

```bash
go run . -cidr 192.168.1.0/24 -ports 1-65535 -timeout 5s
```

Common flags:

```text
-cidr      target CIDR, for example 192.168.1.0/24
-ports     port list/ranges, for example 9,445,5000-5100
-timeout   discovery timeout, default 5s
-json      output JSON instead of text
```

Text output example:

```text
services:
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9
answers:
PTR:
_qdiscover._tcp.local
```

