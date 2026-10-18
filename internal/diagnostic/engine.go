package diagnostic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

const ToolVersion = "0.1.0-dev"

var errRedirectLimit = errors.New("redirect limit exceeded")

// Run performs direct, sequential probes. A failed layer keeps its evidence;
// dependent layers are marked skipped instead of being silently omitted.
func Run(ctx context.Context, input string, options Options) (result Result, err error) {
	target, err := NormalizeTarget(input)
	if err != nil {
		return Result{}, err
	}
	options = options.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, options.TotalTimeout)
	defer cancel()

	start := time.Now()
	result = Result{
		SchemaVersion: 1,
		ToolVersion:   ToolVersion,
		StartedAt:     start.UTC(),
		Target:        target,
	}
	defer func() { result.DurationMs = time.Since(start).Milliseconds() }()

	result.Environment = probeEnvironment()
	if options.ProxyConfig != nil {
		result.Environment.Data.Proxy = *options.ProxyConfig
	}
	progress(options, "environment", result.Environment.Status, result.Environment.DurationMs)
	if options.ProbeSystemProxy {
		proxyData := result.Environment.Data.Proxy
		proxyDone := make(chan Step[HTTPData], 1)
		go func() {
			step := probeProxyHTTP(ctx, target, options, proxyData)
			progress(options, "proxy_http", step.Status, step.DurationMs)
			proxyDone <- step
		}()
		defer func() {
			step := <-proxyDone
			result.ProxyHTTP = &step
		}()
	}
	result.DNS = probeDNS(ctx, target.Host, options.DNSTimeout, options.Resolver)
	progress(options, "dns", result.DNS.Status, result.DNS.DurationMs)
	if result.DNS.Status != StatusSuccess && !(result.DNS.Status == StatusSkipped && result.DNS.Reason == "literal_ip") {
		result.TCP = skipped[TCPData]("tcp", "DNS did not resolve")
		result.TLS = skipped[TLSData]("tls", "DNS did not resolve")
		result.HTTP = skipped[HTTPData]("http", "DNS did not resolve")
		progress(options, "tcp", result.TCP.Status, 0)
		progress(options, "tls", result.TLS.Status, 0)
		progress(options, "http", result.HTTP.Status, 0)
		return result, nil
	}

	result.TCP = probeTCP(ctx, target.Port, *result.DNS.Data, options.TCPTimeout)
	progress(options, "tcp", result.TCP.Status, result.TCP.DurationMs)
	if result.TCP.Status != StatusSuccess {
		result.TLS = skipped[TLSData]("tls", "TCP connection failed")
		result.HTTP = skipped[HTTPData]("http", "TCP connection failed")
		progress(options, "tls", result.TLS.Status, 0)
		progress(options, "http", result.HTTP.Status, 0)
		return result, nil
	}

	if target.Scheme == "https" {
		result.TLS = probeTLS(ctx, target, result.TCP.Data.ConnectedAddress, options)
		progress(options, "tls", result.TLS.Status, result.TLS.DurationMs)
		if result.TLS.Status != StatusSuccess {
			result.HTTP = skipped[HTTPData]("http", "TLS verification or handshake failed")
			progress(options, "http", result.HTTP.Status, 0)
			return result, nil
		}
	} else {
		result.TLS = skipped[TLSData]("tls", "HTTP target does not use TLS")
		progress(options, "tls", result.TLS.Status, 0)
	}
	result.HTTP = probeHTTP(ctx, target, result.TCP.Data.ConnectedAddress, options)
	progress(options, "http", result.HTTP.Status, result.HTTP.DurationMs)
	return result, nil
}

func progress(options Options, id string, status Status, durationMs int64) {
	if options.OnStep != nil {
		options.OnStep(StepProgress{ID: id, Status: status, DurationMs: durationMs})
	}
}

func skipped[T any](id, reason string) Step[T] {
	return Step[T]{ID: id, Status: StatusSkipped, Reason: reason}
}

func probeDNS(parent context.Context, host string, timeout time.Duration, resolver IPResolver) Step[DNSData] {
	step := Step[DNSData]{ID: "dns"}
	if ip := net.ParseIP(host); ip != nil {
		data := DNSData{IPv4: []string{}, IPv6: []string{}}
		if ip.To4() != nil {
			data.IPv4 = append(data.IPv4, ip.String())
		} else {
			data.IPv6 = append(data.IPv6, ip.String())
		}
		step.Status, step.Reason, step.Data = StatusSkipped, "literal_ip", &data
		return step
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	start := time.Now()
	addresses, err := resolver.LookupIPAddr(ctx, host)
	step.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		step.Status = StatusFailure
		step.Error = probeError(err)
		return step
	}
	data := DNSData{IPv4: []string{}, IPv6: []string{}}
	for _, addr := range addresses {
		if addr.IP.To4() != nil {
			data.IPv4 = append(data.IPv4, addr.IP.String())
		} else {
			data.IPv6 = append(data.IPv6, addr.IP.String())
		}
	}
	data.IPv4 = uniqueStrings(data.IPv4)
	data.IPv6 = uniqueStrings(data.IPv6)
	step.Data = &data
	if len(data.IPv4)+len(data.IPv6) == 0 {
		step.Status = StatusFailure
		step.Error = &ProbeError{Kind: "dns_no_addresses", Message: "DNS returned no addresses"}
	} else {
		step.Status = StatusSuccess
	}
	return step
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := values[:0]
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

const maxTCPAddressesPerFamily = 3

// probeTCP samples resolver-ordered addresses from each available family. All
// attempts share one per-layer deadline, so additional addresses cannot make
// this stage wait longer than its configured timeout.
func probeTCP(parent context.Context, port string, dns DNSData, timeout time.Duration) Step[TCPData] {
	step := Step[TCPData]{ID: "tcp"}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	start := time.Now()
	type candidate struct{ family, ip, network string }
	candidates := []candidate{}
	for _, ip := range dns.IPv4[:min(len(dns.IPv4), maxTCPAddressesPerFamily)] {
		candidates = append(candidates, candidate{"IPv4", ip, "tcp4"})
	}
	for _, ip := range dns.IPv6[:min(len(dns.IPv6), maxTCPAddressesPerFamily)] {
		candidates = append(candidates, candidate{"IPv6", ip, "tcp6"})
	}
	type indexedAttempt struct {
		index   int
		attempt TCPAttempt
	}
	results := make(chan indexedAttempt, len(candidates))
	for index, item := range candidates {
		go func(index int, item candidate) {
			address := net.JoinHostPort(item.ip, port)
			attemptStart := time.Now()
			conn, err := (&net.Dialer{}).DialContext(ctx, item.network, address)
			attempt := TCPAttempt{Family: item.family, Address: address, DurationMs: time.Since(attemptStart).Milliseconds()}
			if err != nil {
				attempt.Status = StatusFailure
				attempt.Error = probeError(err)
			} else {
				attempt.Status = StatusSuccess
				conn.Close()
			}
			results <- indexedAttempt{index, attempt}
		}(index, item)
	}
	data := TCPData{Attempts: make([]TCPAttempt, len(candidates))}
	for range candidates {
		result := <-results
		data.Attempts[result.index] = result.attempt
	}
	step.DurationMs = time.Since(start).Milliseconds()
	step.Data = &data
	for _, attempt := range data.Attempts {
		if attempt.Status == StatusSuccess {
			step.Status = StatusSuccess
			data.ConnectedAddress = attempt.Address
			return step
		}
	}
	step.Status = StatusFailure
	if parent.Err() != nil {
		step.Error = probeError(parent.Err())
	} else if ctx.Err() != nil {
		step.Error = probeError(ctx.Err())
	} else if len(data.Attempts) > 0 {
		step.Error = data.Attempts[0].Error
		for _, attempt := range data.Attempts[1:] {
			if attempt.Error == nil || step.Error == nil || attempt.Error.Kind != step.Error.Kind {
				step.Error = &ProbeError{Kind: "unknown", Message: "sampled addresses failed differently"}
				break
			}
		}
	}
	return step
}

func probeTLS(parent context.Context, target Target, connectedAddress string, options Options) Step[TLSData] {
	step := Step[TLSData]{ID: "tls"}
	ctx, cancel := context.WithTimeout(parent, options.TLSTimeout)
	defer cancel()
	start := time.Now()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", connectedAddress)
	if err != nil {
		step.Status = StatusFailure
		step.DurationMs = time.Since(start).Milliseconds()
		step.Error = probeError(err)
		return step
	}
	defer raw.Close()

	serverName := target.Host
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}
	// This connection only inspects the peer certificate. Verification below
	// decides whether the HTTP layer may send a request.
	conn := tls.Client(raw, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	handshakeStart := time.Now()
	err = conn.HandshakeContext(ctx)
	handshakeMs := time.Since(handshakeStart).Milliseconds()
	step.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		step.Status = StatusFailure
		step.Error = &ProbeError{Kind: classifyError(err, "tls_handshake_failed"), Message: err.Error()}
		return step
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		step.Status = StatusFailure
		step.Error = &ProbeError{Kind: "certificate_missing", Message: "server sent no certificate"}
		return step
	}
	cert := state.PeerCertificates[0]
	now := time.Now()
	data := TLSData{
		Protocol:    tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		HandshakeMs: handshakeMs,
		Certificate: CertificateData{
			Subject:   cert.Subject.String(),
			Issuer:    cert.Issuer.String(),
			DNSNames:  append([]string(nil), cert.DNSNames...),
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
		},
		HostnameValid: cert.VerifyHostname(target.Host) == nil,
		TimeValid:     !now.Before(cert.NotBefore) && !now.After(cert.NotAfter),
	}
	intermediates := x509.NewCertPool()
	for _, intermediate := range state.PeerCertificates[1:] {
		intermediates.AddCert(intermediate)
	}
	_, verifyErr := cert.Verify(x509.VerifyOptions{
		DNSName:       target.Host,
		Intermediates: intermediates,
		Roots:         options.RootCAs,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	step.Data = &data
	if verifyErr != nil {
		data.VerifyError = verifyErr.Error()
		step.Status = StatusFailure
		step.Error = &ProbeError{Kind: "certificate_invalid", Message: verifyErr.Error()}
	} else {
		data.Verified = true
		step.Status = StatusSuccess
	}
	return step
}

type captureTransport struct {
	base http.RoundTripper
	hops *[]HTTPHop
}

func (transport captureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	start := time.Now()
	response, err := transport.base.RoundTrip(request)
	if response != nil {
		*transport.hops = append(*transport.hops, HTTPHop{
			URL:        request.URL.String(),
			StatusCode: response.StatusCode,
			DurationMs: time.Since(start).Milliseconds(),
		})
	}
	return response, err
}

func probeHTTP(parent context.Context, target Target, connectedAddress string, options Options) Step[HTTPData] {
	return requestHTTP(parent, target, options, nil, options.HTTPTimeout, "http", "direct", connectedAddress)
}

func requestHTTP(parent context.Context, target Target, options Options, proxyURL *url.URL, timeout time.Duration, id, transport, connectedAddress string) Step[HTTPData] {
	step := Step[HTTPData]{ID: id}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	start := time.Now()
	hops := []HTTPHop{}
	var proxy func(*http.Request) (*url.URL, error)
	if proxyURL != nil {
		proxy = http.ProxyURL(proxyURL)
	}
	base := &http.Transport{
		Proxy:                 proxy,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       &tls.Config{RootCAs: options.RootCAs},
	}
	if proxyURL == nil && connectedAddress != "" {
		dialer := &net.Dialer{}
		base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if strings.EqualFold(address, target.Address) {
				return dialer.DialContext(ctx, "tcp", connectedAddress)
			}
			return dialer.DialContext(ctx, network, address)
		}
	}
	defer base.CloseIdleConnections()
	client := &http.Client{
		Transport: captureTransport{base: base, hops: &hops},
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > options.MaxRedirects {
				return errRedirectLimit
			}
			if request.URL.User != nil || (request.URL.Scheme != "http" && request.URL.Scheme != "https") {
				return fmt.Errorf("unsupported redirect target")
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		step.Status = StatusFailure
		step.Error = probeError(err)
		return step
	}
	response, err := client.Do(request)
	step.DurationMs = time.Since(start).Milliseconds()
	data := HTTPData{Hops: hops, Transport: transport}
	step.Data = &data
	if err != nil {
		step.Status = StatusFailure
		step.Error = probeError(err)
		return step
	}
	defer response.Body.Close()
	data.StatusCode = response.StatusCode
	data.FinalURL = response.Request.URL.String()
	step.Status = StatusSuccess
	return step
}

func probeError(err error) *ProbeError {
	kind := classifyError(err, "unknown")
	if errors.Is(err, errRedirectLimit) {
		kind = "redirect_limit"
	}
	return &ProbeError{Kind: kind, Message: err.Error()}
}

func classifyError(err error, fallback string) string {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return "dns_not_found"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.Errno(10054)):
		return "connection_reset"
	case errors.Is(err, syscall.Errno(10061)): // WSAECONNREFUSED
		return "connection_refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "network_unreachable"
	case errors.Is(err, syscall.Errno(10051)), errors.Is(err, syscall.Errno(10065)):
		return "network_unreachable"
	case errors.Is(err, syscall.Errno(10060)):
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		return "connection_refused"
	}
	return fallback
}
