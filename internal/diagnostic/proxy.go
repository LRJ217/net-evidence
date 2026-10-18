package diagnostic

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// probeProxyHTTP observes the manual Windows proxy path independently of the
// direct layers. PAC scripts and browser-specific proxy rules are not executed.
func probeProxyHTTP(ctx context.Context, target Target, options Options, config ProxyData) Step[HTTPData] {
	step := Step[HTTPData]{ID: "proxy_http"}
	if isLoopbackHost(target.Host) {
		step.Status, step.Reason = StatusSkipped, "local_target"
		return step
	}
	proxyURL, reason := manualProxyURL(config, target.Scheme)
	if proxyURL == nil {
		step.Status, step.Reason = StatusSkipped, reason
		return step
	}
	return requestHTTP(ctx, target, options, proxyURL, options.ProxyTimeout, "proxy_http", "system_proxy")
}

func manualProxyURL(config ProxyData, targetScheme string) (*url.URL, string) {
	if !config.Enabled {
		return nil, "proxy_disabled"
	}
	if strings.TrimSpace(config.Server) == "" {
		if config.AutoConfigURL != "" {
			return nil, "pac_unsupported"
		}
		return nil, "manual_proxy_unavailable"
	}
	type choice struct{ value, kind string }
	choices := map[string]choice{}
	for _, part := range strings.Split(config.Server, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if key, value, ok := strings.Cut(part, "="); ok {
			key = strings.ToLower(strings.TrimSpace(key))
			if key == "http" || key == "https" || key == "socks" {
				choices[key] = choice{strings.TrimSpace(value), key}
			}
		} else {
			choices["default"] = choice{part, "http"}
		}
	}
	selected, ok := choices[targetScheme]
	if !ok {
		selected, ok = choices["socks"]
	}
	if !ok {
		selected, ok = choices["default"]
	}
	if !ok {
		return nil, "manual_proxy_unavailable"
	}
	value := selected.value
	if !strings.Contains(value, "://") {
		prefix := "http://"
		if selected.kind == "socks" {
			prefix = "socks5://"
		}
		value = prefix + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, "manual_proxy_invalid"
	}
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, "manual_proxy_invalid"
	}
	port := parsed.Port()
	if port == "" {
		return nil, "manual_proxy_invalid"
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return nil, "manual_proxy_invalid"
	}
	return parsed, ""
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
