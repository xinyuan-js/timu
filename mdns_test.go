package main

import (
	"bytes"
	"net"
	"sort"
	"strings"
	"testing"
)

func TestBuildAssetsMatchesExampleDepth(t *testing.T) {
	messages := exampleMessages()
	assets := buildAssets(messages)
	sortAssets(assets)

	ports := map[int]bool{9: true, 445: true, 5000: true, 548: true}
	_, cidr, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	assets = filterAssets(assets, cidr, ports)

	if len(assets) != 6 {
		t.Fatalf("assets=%d, want 6: %#v", len(assets), assets)
	}

	qdiscover := findAsset(t, assets, "qdiscover", 5000)
	if qdiscover.IP != "192.168.1.10" {
		t.Fatalf("qdiscover ip=%q", qdiscover.IP)
	}
	if qdiscover.Host != "slw-nas.local" || qdiscover.Name != "slw-nas" {
		t.Fatalf("qdiscover host/name=%q/%q", qdiscover.Host, qdiscover.Name)
	}
	wantBanner := "accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214"
	if qdiscover.TXT != wantBanner {
		t.Fatalf("qdiscover banner=%q, want %q", qdiscover.TXT, wantBanner)
	}

	deviceInfo := findAsset(t, assets, "device-info", 0)
	if deviceInfo.Name != "slw-nas(AFP)" {
		t.Fatalf("device-info name=%q", deviceInfo.Name)
	}
	if deviceInfo.Hostname != "slw-nas.local" {
		t.Fatalf("device-info hostname=%q", deviceInfo.Hostname)
	}
	if deviceInfo.TXT != "model=Xserve" {
		t.Fatalf("device-info banner=%q", deviceInfo.TXT)
	}
}

func TestAnswersPTRContainsOnlyServiceTypes(t *testing.T) {
	answers := buildAnswers(exampleMessages())
	want := []string{
		"_workstation._tcp.local",
		"_http._tcp.local",
		"_smb._tcp.local",
		"_qdiscover._tcp.local",
		"_device-info._tcp.local",
		"_afpovertcp._tcp.local",
	}
	if strings.Join(answers.PTR, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ptr answers=%#v, want %#v", answers.PTR, want)
	}
}

func TestTextOutputMatchesExampleShape(t *testing.T) {
	assets := buildAssets(exampleMessages())
	sortAssets(assets)
	var out bytes.Buffer
	writeText(&out, assets, buildAnswers(exampleMessages()))
	text := out.String()

	required := []string{
		"services:\n",
		"9/tcp workstation:\nName=slw-nas [24:5e:be:69:a3:13]\nIPv4=192.168.1.10\nIPv6=fe80::265e:beff:fe69:a313\nHostname=slw-nas.local\nTTL=10\n",
		"5000/tcp qdiscover:\nName=slw-nas\nIPv4=192.168.1.10\nIPv6=fe80::265e:beff:fe69:a313\nHostname=slw-nas.local\nTTL=10\naccessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214\n",
		"device-info:\nName=slw-nas(AFP)\nIPv4=192.168.1.10\nIPv6=fe80::265e:beff:fe69:a313\nHostname=slw-nas.local\nTTL=10\nmodel=Xserve\n",
		"answers:\nPTR:\n_workstation._tcp.local\n_http._tcp.local\n_smb._tcp.local\n_qdiscover._tcp.local\n_device-info._tcp.local\n_afpovertcp._tcp.local\n",
	}
	for _, part := range required {
		if !strings.Contains(text, part) {
			t.Fatalf("output missing:\n%s\nfull output:\n%s", part, text)
		}
	}
}

func exampleMessages() []dnsMessage {
	const ttl = 10
	host := "slw-nas.local"
	ip4 := net.ParseIP("192.168.1.10").To4()
	ip6 := net.ParseIP("fe80::265e:beff:fe69:a313")
	services := []string{
		"_workstation._tcp.local",
		"_http._tcp.local",
		"_smb._tcp.local",
		"_qdiscover._tcp.local",
		"_device-info._tcp.local",
		"_afpovertcp._tcp.local",
	}
	instances := map[string]string{
		"_workstation._tcp.local": "slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local",
		"_http._tcp.local":        "slw-nas._http._tcp.local",
		"_smb._tcp.local":         "slw-nas._smb._tcp.local",
		"_qdiscover._tcp.local":   "slw-nas._qdiscover._tcp.local",
		"_device-info._tcp.local": "slw-nas(AFP)._device-info._tcp.local",
		"_afpovertcp._tcp.local":  "slw-nas(AFP)._afpovertcp._tcp.local",
	}
	ports := map[string]uint16{
		"slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local": 9,
		"slw-nas._http._tcp.local":                            5000,
		"slw-nas._smb._tcp.local":                             445,
		"slw-nas._qdiscover._tcp.local":                       5000,
		"slw-nas(AFP)._afpovertcp._tcp.local":                 548,
	}

	var records []resourceRecord
	for _, service := range services {
		records = append(records, resourceRecord{Name: serviceEnumName, Type: dnsTypePTR, Class: dnsClassINET, TTL: ttl, Data: service})
		records = append(records, resourceRecord{Name: service, Type: dnsTypePTR, Class: dnsClassINET, TTL: ttl, Data: instances[service]})
	}
	for instance, port := range ports {
		records = append(records, resourceRecord{Name: instance, Type: dnsTypeSRV, Class: dnsClassINET, TTL: ttl, Data: srvRecord{Port: port, Target: host}})
	}
	records = append(records,
		resourceRecord{Name: "slw-nas._http._tcp.local", Type: dnsTypeTXT, Class: dnsClassINET, TTL: ttl, Data: []string{"path=/"}},
		resourceRecord{Name: "slw-nas._qdiscover._tcp.local", Type: dnsTypeTXT, Class: dnsClassINET, TTL: ttl, Data: []string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"}},
		resourceRecord{Name: "slw-nas(AFP)._device-info._tcp.local", Type: dnsTypeTXT, Class: dnsClassINET, TTL: ttl, Data: []string{"model=Xserve"}},
		resourceRecord{Name: host, Type: dnsTypeA, Class: dnsClassINET, TTL: ttl, Data: ip4},
		resourceRecord{Name: host, Type: dnsTypeAAAA, Class: dnsClassINET, TTL: ttl, Data: ip6},
	)
	return []dnsMessage{{Answers: records}}
}

func sortAssets(assets []Asset) {
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].Port != assets[j].Port {
			if assets[i].Port == 0 {
				return false
			}
			if assets[j].Port == 0 {
				return true
			}
			return assets[i].Port < assets[j].Port
		}
		if assets[i].Protocol != assets[j].Protocol {
			return assets[i].Protocol < assets[j].Protocol
		}
		return assets[i].Service < assets[j].Service
	})
}

func findAsset(t *testing.T, assets []Asset, service string, port int) Asset {
	t.Helper()
	for _, asset := range assets {
		if asset.Service == service && asset.Port == port {
			return asset
		}
	}
	t.Fatalf("missing asset service=%s port=%d in %#v", service, port, assets)
	return Asset{}
}
