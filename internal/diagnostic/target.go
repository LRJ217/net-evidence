package diagnostic

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// Target is the explicit endpoint selected by the user. URL may contain a
// sensitive query string and must not be shared before redaction.
type Target struct {
	Input   string `json:"input"`
	URL     string `json:"url"`
	Scheme  string `json:"scheme"`
	Host    string `json:"host"`
	Port    string `json:"port"`
	Address string `json:"address"`
}

// NormalizeTarget accepts HTTP(S) URLs, bare hosts, and host:port pairs.
// A bare host uses HTTPS:443; host:port uses HTTP except for port 443.
func NormalizeTarget(input string) (Target, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return Target{}, fmt.Errorf("target is empty")
	}
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return Target{}, fmt.Errorf("target contains whitespace or control characters")
		}
	}

	var parsed *url.URL
	var err error
	if strings.Contains(raw, "://") {
		parsed, err = url.Parse(raw)
		if err != nil {
			return Target{}, fmt.Errorf("invalid URL: %w", err)
		}
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return Target{}, fmt.Errorf("only http and https URLs are supported")
		}
		if parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" {
			return Target{}, fmt.Errorf("URL must have a host and no user credentials")
		}
	} else {
		if strings.ContainsAny(raw, "/?#@\\") {
			return Target{}, fmt.Errorf("bare target must be a host or host:port")
		}
		host, port := raw, ""
		switch {
		case net.ParseIP(raw) != nil:
			// Bare IPv4 or IPv6 address.
		case strings.HasPrefix(raw, "["):
			host, port, err = net.SplitHostPort(raw)
			if err != nil {
				return Target{}, fmt.Errorf("invalid bracketed host:port: %w", err)
			}
			if port == "" {
				return Target{}, fmt.Errorf("port is missing")
			}
		case strings.Count(raw, ":") == 1:
			host, port, err = net.SplitHostPort(raw)
			if err != nil {
				return Target{}, fmt.Errorf("invalid host:port: %w", err)
			}
			if port == "" {
				return Target{}, fmt.Errorf("port is missing")
			}
		case strings.Contains(raw, ":"):
			return Target{}, fmt.Errorf("IPv6 host:port must use brackets")
		}
		scheme := "https"
		if port != "" && port != "443" {
			scheme = "http"
		}
		parsed = &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port)}
	}

	host := parsed.Hostname()
	if host == "" || strings.Contains(host, "%") {
		return Target{}, fmt.Errorf("invalid host")
	}
	if net.ParseIP(host) == nil {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || !validHostname(host) {
			return Target{}, fmt.Errorf("invalid domain name")
		}
		host = strings.ToLower(host)
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return Target{}, fmt.Errorf("port must be between 1 and 65535")
	}
	port = strconv.Itoa(number)
	parsed.Host = net.JoinHostPort(host, port)
	parsed.Fragment = ""
	parsed.RawFragment = ""
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return Target{
		Input:   raw,
		URL:     parsed.String(),
		Scheme:  parsed.Scheme,
		Host:    host,
		Port:    port,
		Address: net.JoinHostPort(host, port),
	}, nil
}

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}
