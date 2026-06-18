package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	mdnsAddr4       = "224.0.0.251:5353"
	mdnsAddr6       = "[ff02::fb]:5353"
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
	responses4, err4 := discoverUDP("udp4", mdnsAddr4, timeout)
	responses6, err6 := discoverUDP("udp6", mdnsAddr6, timeout)
	responses := append(responses4, responses6...)
	if len(responses) == 0 && err4 != nil && err6 != nil {
		return nil, Answers{}, err4
	}

	return buildAssets(responses), buildAnswers(responses), nil
}

func discoverUDP(network string, address string, timeout time.Duration) ([]dnsMessage, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenMulticastUDP(network, nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetReadBuffer(1 << 20); err != nil {
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if err := sendQuery(conn, addr, serviceEnumName, dnsTypePTR); err != nil {
		return nil, err
	}

	phaseTimeout := timeout / 4
	if phaseTimeout < 250*time.Millisecond {
		phaseTimeout = timeout
	}

	deadline := time.Now().Add(phaseTimeout)
	responses, serviceTypes := collect(conn, deadline, nil)
	for serviceType := range serviceTypes {
		_ = sendQuery(conn, addr, serviceType, dnsTypePTR)
	}
	deadline = time.Now().Add(phaseTimeout)
	more, _ := collect(conn, deadline, serviceTypes)
	responses = append(responses, more...)

	instances, targets := discoverNames(responses)
	for instance := range instances {
		_ = sendQuery(conn, addr, instance, dnsTypeSRV)
		_ = sendQuery(conn, addr, instance, dnsTypeTXT)
	}
	deadline = time.Now().Add(phaseTimeout)
	more, _ = collect(conn, deadline, serviceTypes)
	responses = append(responses, more...)

	_, targets = discoverNames(responses)
	for target := range targets {
		_ = sendQuery(conn, addr, target, dnsTypeA)
		_ = sendQuery(conn, addr, target, dnsTypeAAAA)
	}
	deadline = time.Now().Add(phaseTimeout)
	more, _ = collect(conn, deadline, serviceTypes)
	responses = append(responses, more...)

	return responses, nil
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
	var out []string
	seen := make(map[string]bool)
	for _, msg := range messages {
		for _, rr := range msg.allRecords() {
			if rr.Type != dnsTypePTR || !strings.EqualFold(trimDot(rr.Name), serviceEnumName) {
				continue
			}
			value, ok := rr.Data.(string)
			if !ok {
				continue
			}
			ptr := trimDot(value)
			if !seen[ptr] {
				seen[ptr] = true
				out = append(out, ptr)
			}
		}
	}
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

	knownHostIPv4 := firstMapValue(hostIPv4)
	knownHostIPv6 := firstMapValue(hostIPv6)
	var assets []Asset
	for _, info := range instances {
		if info.Type == "" {
			continue
		}
		if info.Target == "" {
			info.Target = inferHostname(instanceName(info.Instance, info.Type))
		}
		proto, service := splitService(info.Type)
		ipv4 := sortedKeys(hostIPv4[info.Target])
		ipv6 := sortedKeys(hostIPv6[info.Target])
		if len(ipv4) == 0 && len(knownHostIPv4) > 0 {
			ipv4 = knownHostIPv4
		}
		if len(ipv6) == 0 && len(knownHostIPv6) > 0 {
			ipv6 = knownHostIPv6
		}
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
			TXT:      strings.Join(uniquePreserveOrder(info.TXT), ","),
		})
	}
	return assets
}

func discoverNames(messages []dnsMessage) (map[string]bool, map[string]bool) {
	instances := make(map[string]bool)
	targets := make(map[string]bool)
	for _, msg := range messages {
		for _, rr := range msg.allRecords() {
			name := trimDot(rr.Name)
			switch rr.Type {
			case dnsTypePTR:
				if strings.EqualFold(name, serviceEnumName) {
					continue
				}
				if ptr, ok := rr.Data.(string); ok {
					instances[trimDot(ptr)] = true
				}
			case dnsTypeSRV:
				if srv, ok := rr.Data.(srvRecord); ok {
					targets[trimDot(srv.Target)] = true
				}
			}
		}
	}
	return instances, targets
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

func inferHostname(name string) string {
	base := name
	if idx := strings.Index(base, "("); idx > 0 {
		base = strings.TrimSpace(base[:idx])
	}
	base = strings.TrimSpace(base)
	if strings.HasSuffix(base, ".local") {
		return base
	}
	if base == "" {
		return ""
	}
	return base + ".local"
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniquePreserveOrder(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func firstMapValue(values map[string]map[string]bool) []string {
	var best []string
	for _, ips := range values {
		current := sortedKeys(ips)
		if len(best) == 0 || strings.Join(current, ",") < strings.Join(best, ",") {
			best = current
		}
	}
	return best
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
