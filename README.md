# mdns-mapper

`mdns-mapper` is a Go CLI for discovering mDNS assets in an IP CIDR and port
range. It is intended for local-network asset mapping through the mDNS/DNS-SD
protocol.

It sends standard mDNS multicast PTR queries, follows discovered service types, and prints
matched assets with `ip`, `port`, `host`, and a deeper banner assembled from mDNS records
(`Name`, `IPv4`, `IPv6`, `Hostname`, `TTL`, and TXT key/value data).

## Features

- Accepts an IP CIDR and a port list/range from CLI flags.
- Discovers mDNS/DNS-SD service types through `_services._dns-sd._udp.local`.
- Follows service PTR records to service instances.
- Queries service instances for `SRV` and `TXT` records.
- Queries SRV target hostnames for `A` and `AAAA` records.
- Outputs service assets with `ip`, `port`, `host`, `Name`, `IPv4`, `IPv6`,
  `Hostname`, `TTL`, and TXT banner content.
- Preserves TXT record order so vendor banners keep their original semantic
  shape, for example `accessType=https,accessPort=86,model=...`.
- Supports no-port metadata services such as `device-info:` when they belong
  to a matching host.
- Supports text output and JSON output.

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

## Output

Default text output follows the shape below:

```text
services:
<port>/<proto> <service>:
Name=<instance name>
IPv4=<matched IPv4>
IPv6=<matched IPv6>
Hostname=<service target host>
TTL=<record ttl>
<TXT banner joined by comma>
answers:
PTR:
<service type PTR>
```

Text output example:

```text
services:
9/tcp workstation:
Name=slw-nas [24:5e:be:69:a3:13]
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
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
_qdiscover._tcp.local
_device-info._tcp.local
```

JSON output is available with `-json`:

```bash
go run . -cidr 192.168.1.0/24 -ports 9,445,5000-5100 -json
```

## Implementation

The discovery pipeline is deliberately small and dependency-free. It uses only
the Go standard library and a local DNS parser for the record types needed by
mDNS asset mapping.

1. Send a PTR query for `_services._dns-sd._udp.local` to discover advertised
   service types such as `_http._tcp.local`, `_smb._tcp.local`, and
   `_qdiscover._tcp.local`.
2. Query each discovered service type for PTR answers. These answers point to
   concrete service instances, for example `slw-nas._qdiscover._tcp.local`.
3. Query every service instance for `SRV` and `TXT`. `SRV` gives the target
   hostname and port; `TXT` is treated as the deep-recognition banner.
4. Query every SRV target hostname for `A` and `AAAA` records.
5. Merge PTR, SRV, TXT, A, and AAAA records into asset entries.
6. Filter assets by the input CIDR and port range.
7. Print text output in the required example shape, or structured JSON when
   `-json` is set.

IPv4 mDNS uses `224.0.0.251:5353`. IPv6 mDNS uses `ff02::fb:5353` when the
local machine and network stack support it. The scanner runs IPv4 and IPv6
probing independently; if one protocol is unavailable, the other can still
produce results.

## Asset Matching Notes

- Port-bearing services must match the requested port range.
- No-port metadata records such as `device-info:` are kept only when their IP
  belongs to the requested CIDR.
- The implementation does not borrow an IP address from an unrelated host. If a
  metadata-only service has no matching `A` or `AAAA` record for its inferred
  hostname, it is left without an IP and will not pass CIDR filtering.
- TXT values are de-duplicated while preserving original mDNS order.

## Tests

Run all tests:

```bash
go test ./...
```

The test suite covers:

- port range parsing;
- DNS name compression parsing;
- example-level mDNS asset building;
- `qdiscover` deep TXT banner order;
- no-port `device-info:` output;
- `answers: PTR:` service-type filtering;
- protection against borrowing IP addresses from unrelated hosts;
- IPv4/IPv6 discovery error policy.

