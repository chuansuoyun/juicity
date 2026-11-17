package portlist

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Parse parses port specs like "443", "20000-30000", "443,20000-20010".
func Parse(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port list")
	}
	seen := make(map[int]struct{})
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			if len(ab) != 2 {
				return nil, fmt.Errorf("invalid port range: %q", part)
			}
			lo, err := strconv.Atoi(strings.TrimSpace(ab[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range start: %q", part)
			}
			hi, err := strconv.Atoi(strings.TrimSpace(ab[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range end: %q", part)
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid port range bounds: %q", part)
			}
			// Cap expansion to avoid huge memory (e.g. 1-65535).
			if hi-lo+1 > 10000 {
				return nil, fmt.Errorf("port range too large (max 10000 ports): %q", part)
			}
			for p := lo; p <= hi; p++ {
				if _, ok := seen[p]; ok {
					continue
				}
				seen[p] = struct{}{}
				out = append(out, p)
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port: %q", part)
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports parsed from %q", spec)
	}
	return out, nil
}

// HostOf extracts host from "host:port", "host:port-port" is invalid for SplitHostPort;
// use HostOfServer for juicity "server" field.
func HostOfServer(server string) (host string, portFromServer string, err error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", "", fmt.Errorf("empty server")
	}
	// host:port (single)
	if h, p, e := net.SplitHostPort(server); e == nil {
		return h, p, nil
	}
	// bare host / IP
	if strings.Contains(server, ":") && !strings.HasPrefix(server, "[") {
		// likely unbracketed IPv6 without port — require brackets
		return "", "", fmt.Errorf("invalid server address %q (use host:port or [ipv6]:port)", server)
	}
	return server, "", nil
}
