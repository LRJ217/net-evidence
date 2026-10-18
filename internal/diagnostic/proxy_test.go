package diagnostic

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManualProxySelection(t *testing.T) {
	tests := []struct {
		name, server, scheme, wantURL, wantReason string
		enabled                                   bool
	}{
		{"single", "127.0.0.1:7890", "https", "http://127.0.0.1:7890", "", true},
		{"per protocol", "http=127.0.0.1:8080;https=127.0.0.1:8443", "https", "http://127.0.0.1:8443", "", true},
		{"socks fallback", "socks=127.0.0.1:1080", "https", "socks5://127.0.0.1:1080", "", true},
		{"wrong protocol", "http=127.0.0.1:8080", "https", "", "manual_proxy_unavailable", true},
		{"bad port", "127.0.0.1:99999", "https", "", "manual_proxy_invalid", true},
		{"disabled", "127.0.0.1:7890", "https", "", "proxy_disabled", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := manualProxyURL(ProxyData{Enabled: tc.enabled, Server: tc.server}, tc.scheme)
			if reason != tc.wantReason || (got == nil && tc.wantURL != "") || (got != nil && got.String() != tc.wantURL) {
				t.Fatalf("proxy=%v reason=%q", got, reason)
			}
		})
	}
	if got, reason := manualProxyURL(ProxyData{Enabled: true, AutoConfigURL: "http://private/pac"}, "https"); got != nil || reason != "pac_unsupported" {
		t.Fatalf("PAC handling: %v %q", got, reason)
	}
}

func TestProxyCanRespondWhenLocalDNSFails(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "missing.invalid:80" {
			t.Errorf("wrong proxy target: %s", r.URL)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	var mu sync.Mutex
	progress := []StepProgress{}
	result, err := Run(context.Background(), "http://missing.invalid", Options{
		Resolver: missingResolver{}, ProbeSystemProxy: true,
		ProxyConfig: &ProxyData{Enabled: true, Server: proxyURL.Host},
		OnStep: func(step StepProgress) {
			mu.Lock()
			progress = append(progress, step)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.DNS.Status != StatusFailure || result.TCP.Status != StatusSkipped || result.ProxyHTTP == nil ||
		result.ProxyHTTP.Status != StatusSuccess || result.ProxyHTTP.Data.StatusCode != http.StatusNoContent {
		t.Fatalf("paths were not independent: %+v", result)
	}
	if len(progress) != 6 {
		t.Fatalf("expected six progress events, got %+v", progress)
	}
}

func TestHTTPSRequestUsesProxyConnect(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	var mu sync.Mutex
	connects := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("expected CONNECT, got %s", r.Method)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		connects++
		mu.Unlock()
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		downstream, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		_, _ = downstream.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() { _, _ = io.Copy(upstream, downstream); upstream.Close() }()
		go func() { _, _ = io.Copy(downstream, upstream); downstream.Close() }()
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	endpoint, err := NormalizeTarget(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	selected, reason := manualProxyURL(ProxyData{Enabled: true, Server: "https=" + proxyURL.Host}, "https")
	if reason != "" {
		t.Fatalf("proxy not selected: %s", reason)
	}
	step := requestHTTP(context.Background(), endpoint, Options{RootCAs: roots}.withDefaults(), selected, 5*time.Second, "proxy_http", "system_proxy", "")
	if step.Status != StatusSuccess || step.Data.StatusCode != http.StatusNoContent {
		t.Fatalf("HTTPS proxy path failed: %+v", step)
	}
	mu.Lock()
	defer mu.Unlock()
	if connects == 0 {
		t.Fatal("HTTPS request did not use CONNECT")
	}
}

func TestProxySkipReasons(t *testing.T) {
	target, err := NormalizeTarget("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	step := probeProxyHTTP(context.Background(), target, Options{}.withDefaults(), ProxyData{Enabled: true, Server: "127.0.0.1:7890"})
	if step.Status != StatusSkipped || !strings.EqualFold(step.Reason, "local_target") {
		t.Fatalf("loopback should skip proxy: %+v", step)
	}
}

func TestManualProxyBypass(t *testing.T) {
	for _, tc := range []struct {
		name, list, host string
		want             bool
	}{
		{"exact case insensitive", "EXAMPLE.COM", "example.com", true},
		{"wildcard subdomain", "*.example.com; other.local", "api.example.com", true},
		{"wildcard does not match apex", "*.example.com", "example.com", false},
		{"local hostname", "<local>", "intranet", true},
		{"local excludes dotted host", "<local>", "intranet.example", false},
		{"literal IP", "192.168.*", "192.168.1.2", true},
		{"unrelated", "*.example.com", "youtube.com", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesProxyBypass(tc.list, tc.host); got != tc.want {
				t.Fatalf("matchesProxyBypass(%q, %q) = %v", tc.list, tc.host, got)
			}
		})
	}
	target, err := NormalizeTarget("https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	step := probeProxyHTTP(context.Background(), target, Options{}.withDefaults(), ProxyData{
		Enabled: true, Server: "127.0.0.1:1", BypassList: "*.example.com",
	})
	if step.Status != StatusSkipped || step.Reason != "proxy_bypass" {
		t.Fatalf("manual proxy probe should be skipped: %+v", step)
	}
}
