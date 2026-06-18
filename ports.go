package main

import (
	"fmt"
	"strconv"
	"strings"
)

func parsePortSet(input string) (map[int]bool, error) {
	result := make(map[int]bool)
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := parsePort(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(bounds[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("range %q starts after it ends", part)
			}
			for port := start; port <= end; port++ {
				result[port] = true
			}
			continue
		}
		port, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		result[port] = true
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no ports selected")
	}
	return result, nil
}

func parsePort(input string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil {
		return 0, fmt.Errorf("bad port %q", input)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d outside 1-65535", port)
	}
	return port, nil
}
