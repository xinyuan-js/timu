package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	if timeout <= 0 {
		exitf("invalid -timeout: must be greater than 0")
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
	matchedHosts := make(map[string]bool)
	matchedIPs := make(map[string]bool)

	for _, asset := range in {
		if asset.Port == 0 || !ports[asset.Port] || !assetInCIDR(asset, ipNet) {
			continue
		}
		out = append(out, asset)
		if asset.Host != "" {
			matchedHosts[asset.Host] = true
		}
		for _, ip := range append(asset.IPv4, asset.IPv6...) {
			matchedIPs[ip] = true
		}
	}

	for _, asset := range in {
		if asset.Port != 0 {
			continue
		}
		if assetInCIDR(asset, ipNet) {
			if matchedHosts[asset.Host] || assetSharesMatchedIP(asset, matchedIPs) {
				out = append(out, asset)
			}
		}
	}
	return out
}

func assetSharesMatchedIP(asset Asset, matchedIPs map[string]bool) bool {
	for _, ip := range append(asset.IPv4, asset.IPv6...) {
		if matchedIPs[ip] {
			return true
		}
	}
	return false
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
	writeText(os.Stdout, assets, answers)
}

func writeText(w io.Writer, assets []Asset, answers Answers) {
	fmt.Fprintln(w, "services:")
	for _, asset := range assets {
		if asset.Port > 0 {
			fmt.Fprintf(w, "%d/%s %s:\n", asset.Port, asset.Protocol, asset.Service)
		} else {
			fmt.Fprintf(w, "%s:\n", asset.Service)
		}
		fmt.Fprintf(w, "Name=%s\n", asset.Name)
		for _, ip := range asset.IPv4 {
			fmt.Fprintf(w, "IPv4=%s\n", ip)
		}
		for _, ip := range asset.IPv6 {
			fmt.Fprintf(w, "IPv6=%s\n", ip)
		}
		fmt.Fprintf(w, "Hostname=%s\n", asset.Hostname)
		fmt.Fprintf(w, "TTL=%d\n", asset.TTL)
		if asset.TXT != "" {
			fmt.Fprintln(w, asset.TXT)
		}
	}
	fmt.Fprintln(w, "answers:")
	fmt.Fprintln(w, "PTR:")
	for _, ptr := range answers.PTR {
		fmt.Fprintln(w, ptr)
	}
}
