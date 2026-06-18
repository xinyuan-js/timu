package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	var cidrText string
	var portsText string
	var timeout time.Duration
	var jsonOut bool

	flag.StringVar(&cidrText, "cidr", "", "target CIDR, for example 192.168.1.0/24")
	flag.StringVar(&portsText, "ports", "1-65535", "ports/ranges, for example 9,445,5000-5100")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "mDNS discovery timeout")
	flag.BoolVar(&jsonOut, "json", false, "output JSON")
	flag.Parse()

	if strings.TrimSpace(cidrText) == "" {
		exitf("missing -cidr")
	}

	_, ipNet, err := net.ParseCIDR(cidrText)
	if err != nil {
		exitf("invalid -cidr: %v", err)
	}
	ports, err := parsePortSet(portsText)
	if err != nil {
		exitf("invalid -ports: %v", err)
	}

	assets, answers, err := Discover(timeout)
	if err != nil {
		exitf("mDNS discovery failed: %v", err)
	}
	assets = filterAssets(assets, ipNet, ports)

	sort.Slice(assets, func(i, j int) bool {
		if assets[i].Port != assets[j].Port {
			return assets[i].Port < assets[j].Port
		}
		if assets[i].Protocol != assets[j].Protocol {
			return assets[i].Protocol < assets[j].Protocol
		}
		return assets[i].Service < assets[j].Service
	})

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"services": assets, "answers": answers}); err != nil {
			exitf("json output failed: %v", err)
		}
		return
	}

	printText(assets, answers)
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func filterAssets(in []Asset, ipNet *net.IPNet, ports map[int]bool) []Asset {
	out := make([]Asset, 0, len(in))
	for _, asset := range in {
		if !ports[asset.Port] {
			continue
		}
		if assetInCIDR(asset, ipNet) {
			out = append(out, asset)
		}
	}
	return out
}

func assetInCIDR(asset Asset, ipNet *net.IPNet) bool {
	for _, ipText := range asset.IPv4 {
		if ip := net.ParseIP(ipText); ip != nil && ipNet.Contains(ip) {
			return true
		}
	}
	for _, ipText := range asset.IPv6 {
		if ip := net.ParseIP(ipText); ip != nil && ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func printText(assets []Asset, answers Answers) {
	fmt.Println("services:")
	for _, asset := range assets {
		fmt.Printf("%d/%s %s:\n", asset.Port, asset.Protocol, asset.Service)
		fmt.Printf("Name=%s\n", asset.Name)
		for _, ip := range asset.IPv4 {
			fmt.Printf("IPv4=%s\n", ip)
		}
		for _, ip := range asset.IPv6 {
			fmt.Printf("IPv6=%s\n", ip)
		}
		fmt.Printf("Hostname=%s\n", asset.Hostname)
		fmt.Printf("TTL=%d\n", asset.TTL)
		if asset.TXT != "" {
			fmt.Println(asset.TXT)
		}
	}
	fmt.Println("answers:")
	fmt.Println("PTR:")
	for _, ptr := range answers.PTR {
		fmt.Println(ptr)
	}
}
