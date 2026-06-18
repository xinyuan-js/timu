package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	mdnsAddr        = "224.0.0.251:5353"
	dnsTypeA        = 1
	dnsTypePTR      = 12
	dnsTypeTXT      = 16
	dnsTypeAAAA     = 28
	dnsTypeSRV      = 33
	dnsClassINET    = 1
	serviceEnumName = "_services._dns-sd._udp.local"
)

type Asset struct {
	IP       string   `json:"ip"`
	Port     int      `json:"port"`
	Host     string   `json:"host"`
	Service  string   `json:"service"`
	Protocol string   `json:"protocol"`
	Name     string   `json:"name"`
	IPv4     []string `json:"ipv4,omitempty"`
	IPv6     []string `json:"ipv6,omitempty"`
	Hostname string   `json:"hostname"`
	TTL      uint32   `json:"ttl"`
	TXT      string   `json:"banner,omitempty"`
}

type Answers struct {
	PTR []string `json:"ptr"`
}

type instanceInfo struct {
	Instance string
	Type     string
	Target   string
	Port     int
	TTL      uint32
	TXT      []string
}

func Discover(timeout time.Duration) ([]Asset, Answers, error) {
	addr, err := net.ResolveUDPAddr("udp4", mdnsAddr)
	if err != nil {
		return nil, Answers{}, err
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return nil, Answers{}, err
	}
	defer conn.Close()
	if err := conn.SetReadBuffer(1 << 20); err != nil {
		return nil, Answers{}, err
	}

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, Answers{}, err
	}

	if err := sendQuery(conn, addr, serviceEnumName, dnsTypePTR); err != nil {
		return nil, Answers{}, err
	}

	responses, serviceTypes := collect(conn, deadline, nil)
	for serviceType := range serviceTypes {
		_ = sendQuery(conn, addr, serviceType, dnsTypePTR)
	}
	more, _ := collect(conn, deadline, serviceTypes)
	responses = append(responses, more...)

	return buildAssets(responses), buildAnswers(responses), nil
}

func sendQuery(conn *net.UDPConn, addr *net.UDPAddr, name string, qtype uint16) error {
	packet, err := buildQuery(name, qtype)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDP(packet, addr)
	return err
}

func collect(conn *net.UDPConn, deadline time.Time, knownTypes map[string]bool) ([]dnsMessage, map[string]bool) {
	var messages []dnsMessage
	serviceTypes := make(map[string]bool)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if knownTypes == nil && len(serviceTypes) > 0 {
					return messages, serviceTypes
				}
				continue
			}
			return messages, serviceTypes
		}
		msg, err := parseDNSMessage(buf[:n])
		if err != nil {
			continue
		}
		messages = append(messages, msg)
		for _, rr := range msg.allRecords() {
			if rr.Type == dnsTypePTR && strings.EqualFold(trimDot(rr.Name), serviceEnumName) {
				if ptr, ok := rr.Data.(string); ok {
					serviceTypes[trimDot(ptr)] = true
				}
			}
		}
	}
	return messages, serviceTypes
}

func buildAnswers(messages []dnsMessage) Answers {
	ptrs := make(map[string]bool)
	for _, msg := range messages {
		for _, rr := range msg.allRecords() {
			if rr.Type == dnsTypePTR {
				if value, ok := rr.Data.(string); ok {
					ptrs[trimDot(value)] = true
				}
			}
		}
	}
	out := make([]string, 0, len(ptrs))
	for ptr := range ptrs {
		out = append(out, ptr)
	}
	sort.Strings(out)
	return Answers{PTR: out}
}

func buildAssets(messages []dnsMessage) []Asset {
	instances := make(map[string]*instanceInfo)
	hostIPv4 := make(map[string]map[string]bool)
	hostIPv6 := make(map[string]map[string]bool)

	for _, msg := range messages {
		for _, rr := range msg.allRecords() {
			name := trimDot(rr.Name)
			switch rr.Type {
			case dnsTypePTR:
				ptr, ok := rr.Data.(string)
				if !ok || strings.EqualFold(name, serviceEnumName) {
					continue
				}
				ptr = trimDot(ptr)
				info := getInstance(instances, ptr)
				info.Instance = ptr
				info.Type = name
				if rr.TTL > info.TTL {
					info.TTL = rr.TTL
				}
			case dnsTypeSRV:
				srv, ok := rr.Data.(srvRecord)
				if !ok {
					continue
				}
				info := getInstance(instances, name)
				info.Target = trimDot(srv.Target)
				info.Port = int(srv.Port)
				if rr.TTL > info.TTL {
					info.TTL = rr.TTL
				}
			case dnsTypeTXT:
				txt, ok := rr.Data.([]string)
				if !ok {
					continue
				}
				info := getInstance(instances, name)
				info.TXT = append(info.TXT, txt...)
				if rr.TTL > info.TTL {
					info.TTL = rr.TTL
				}
			case dnsTypeA:
				ip, ok := rr.Data.(net.IP)
				if ok {
					addIP(hostIPv4, name, ip.String())
				}
			case dnsTypeAAAA:
				ip, ok := rr.Data.(net.IP)
				if ok {
					addIP(hostIPv6, name, ip.String())
				}
			}
		}
	}

	var assets []Asset
	for _, info := range instances {
		if info.Port == 0 || info.Target == "" {
			continue
		}
		proto, service := splitService(info.Type)
		ipv4 := sortedKeys(hostIPv4[info.Target])
		ipv6 := sortedKeys(hostIPv6[info.Target])
		name := instanceName(info.Instance, info.Type)
		primaryIP := ""
		if len(ipv4) > 0 {
			primaryIP = ipv4[0]
		} else if len(ipv6) > 0 {
			primaryIP = ipv6[0]
		}
		assets = append(assets, Asset{
			IP:       primaryIP,
			Port:     info.Port,
			Host:     info.Target,
			Service:  service,
			Protocol: proto,
			Name:     name,
			IPv4:     ipv4,
			IPv6:     ipv6,
			Hostname: info.Target,
			TTL:      info.TTL,
			TXT:      strings.Join(uniqueSorted(info.TXT), ","),
		})
	}
	return assets
}

func getInstance(instances map[string]*instanceInfo, name string) *instanceInfo {
	if instances[name] == nil {
		instances[name] = &instanceInfo{Instance: name}
	}
	return instances[name]
}

func addIP(hosts map[string]map[string]bool, host, ip string) {
	if hosts[host] == nil {
		hosts[host] = make(map[string]bool)
	}
	hosts[host][ip] = true
}

func splitService(serviceType string) (proto, service string) {
	parts := strings.Split(strings.Trim(serviceType, "."), ".")
	if len(parts) >= 2 {
		service = strings.TrimPrefix(parts[0], "_")
		proto = strings.TrimPrefix(parts[1], "_")
		return proto, service
	}
	return "tcp", strings.TrimPrefix(serviceType, "_")
}

func instanceName(instance, serviceType string) string {
	suffix := "." + strings.Trim(serviceType, ".")
	return strings.TrimSuffix(instance, suffix)
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool)
	for _, value := range values {
		if value != "" {
			seen[value] = true
		}
	}
	return sortedKeys(seen)
}

func trimDot(input string) string {
	return strings.TrimSuffix(input, ".")
}

func buildQuery(name string, qtype uint16) ([]byte, error) {
	var out []byte
	out = append(out, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	encoded, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	out = append(out, encoded...)
	out = appendUint16(out, qtype)
	out = appendUint16(out, dnsClassINET)
	return out, nil
}

func encodeName(name string) ([]byte, error) {
	var out []byte
	for _, label := range strings.Split(strings.Trim(name, "."), ".") {
		if len(label) > 63 {
			return nil, fmt.Errorf("dns label too long: %q", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out, nil
}

func appendUint16(out []byte, value uint16) []byte {
	return append(out, byte(value>>8), byte(value))
}
