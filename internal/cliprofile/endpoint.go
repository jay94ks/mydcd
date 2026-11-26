// SPDX-License-Identifier: Apache-2.0

// Package cliprofile owns the CLI's local files: contexts (where to connect,
// as whom) and confirmed node keys. It grants no remote authority.
package cliprofile

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
)

var (
	ErrInput     = errors.New("invalid CLI profile input")
	ErrSelection = errors.New("CLI target selection conflict or missing target")
	ErrTrust     = errors.New("CLI profile and trusted node keys do not match")
)

const DefaultEndpoint = "unix:///var/run/mydc.sock"

type Endpoint struct{ URI, Network, Address string }

// ParseEndpoint accepts an absolute socket path only at the CLI input boundary.
// Stored profiles and trusted endpoints use explicit, canonical URIs.
func ParseEndpoint(raw string, allowPath bool) (Endpoint, error) {
	if raw == "" {
		raw = DefaultEndpoint
	}
	if allowPath && strings.HasPrefix(raw, "/") {
		raw = "unix://" + raw
	}
	if strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n\t\\?#") {
		return Endpoint{}, ErrInput
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" {
		return Endpoint{}, ErrInput
	}
	switch u.Scheme {
	case "unix":
		if u.Host != "" || u.Path == "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/") || u.Path == "/" || path.Clean(u.Path) != u.Path || strings.ContainsAny(u.Path, "\x00\r\n\t\\") || len(u.Path) > 107 {
			return Endpoint{}, ErrInput
		}
		canonical := "unix://" + u.Path
		if raw != canonical {
			return Endpoint{}, ErrInput
		}
		return Endpoint{canonical, "unix", u.Path}, nil
	case "mydcp":
		if u.Path != "" || u.RawPath != "" || u.Host == "" {
			return Endpoint{}, ErrInput
		}
		host, port, err := net.SplitHostPort(u.Host)
		n, e := strconv.Atoi(port)
		if err != nil || e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || host == "" {
			return Endpoint{}, ErrInput
		}
		if ip, e := netip.ParseAddr(host); e == nil {
			if ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
				return Endpoint{}, ErrInput
			}
			host = ip.String()
		} else {
			if len(host) > 253 || strings.Contains(host, ":") {
				return Endpoint{}, ErrInput
			}
			host = strings.ToLower(host)
			for _, label := range strings.Split(host, ".") {
				if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
					return Endpoint{}, ErrInput
				}
				for _, c := range []byte(label) {
					if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
						return Endpoint{}, ErrInput
					}
				}
			}
		}
		address := net.JoinHostPort(host, port)
		return Endpoint{"mydcp://" + address, "mydcp", address}, nil
	default:
		return Endpoint{}, ErrInput
	}
}

// Name is a local filename component, not a remote identity or authorization.
func ValidName(s string) bool {
	return s != "default" && s != "default.yaml" && s != ".profile.yaml" && ValidKeyName(s)
}

// ValidKeyName validates wallet names without the profile-path reservations.
func ValidKeyName(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '_' || c == '-')) {
			return false
		}
	}
	return true
}
