package diagnostic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
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
	result.DNS = probeDNS(ctx, target.Host, options.DNSTimeout, options.Resolver)
	if result.DNS.Status != StatusSuccess {
		result.TCP = skipped[TCPData]("tcp", "DNS did not resolve")
		result.TLS = skipped[TLSData]("tls", "DNS did not resolve")
		result.HTTP = skipped[HTTPData]("http", "DNS did not resolve")
		return result, nil
	}

	result.TCP = probeTCP(ctx, target.Address, options.TCPTimeout)
	if result.TCP.Status != StatusSuccess {
		result.TLS = skipped[TLSData]("tls", "TCP connection failed")
		result.HTTP = skipped[HTTPData]("http", "TCP connection failed")
		return result, nil
	}

	if target.Scheme == "https" {
		result.TLS = probeTLS(ctx, target, options)
		if result.TLS.Status != StatusSuccess {
			result.HTTP = skipped[HTTPData]("http", "TLS verification or handshake failed")
			return result, nil
		}
	} else {
		result.TLS = skipped[TLSData]("tls", "HTTP target does not use TLS")
	}
	result.HTTP = probeHTTP(ctx, target, options)
	return result, nil
}

func skipped[T any](id, reason string) Step[T] {
	return Step[T]{ID: id, Status: StatusSkipped, Reason: reason}
}

func probeDNS(parent context.Context, host string, timeout time.Duration, resolver IPResolver) Step[DNSData] {
	step := Step[DNSData]{ID: "dns"}
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
	sort.Strings(data.IPv4)
	sort.Strings(data.IPv6)
	data.IPv4 = compactStrings(data.IPv4)
	data.IPv6 = compactStrings(data.IPv6)
	step.Data = &data
	if len(data.IPv4)+len(data.IPv6) == 0 {
		step.Status = StatusFailure
		step.Error = &ProbeError{Kind: "dns_no_addresses", Message: "DNS returned no addresses"}
	} else {
		step.Status = StatusSuccess
	}
	return step
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func probeTCP(parent context.Context, address string, timeout time.Duration) Step[TCPData] {
	step := Step[TCPData]{ID: "tcp"}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	step.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		step.Status = StatusFailure
		step.Error = probeError(err)
		return step
	}
	defer conn.Close()
	step.Status = StatusSuccess
	step.Data = &TCPData{ConnectedAddress: conn.RemoteAddr().String()}
	return step
}

func probeTLS(parent context.Context, target Target, options Options) Step[TLSData] {
	step := Step[TLSData]{ID: "tls"}
	ctx, cancel := context.WithTimeout(parent, options.TLSTimeout)
	defer cancel()
	start := time.Now()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", target.Address)
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

func probeHTTP(parent context.Context, target Target, options Options) Step[HTTPData] {
	step := Step[HTTPData]{ID: "http"}
	ctx, cancel := context.WithTimeout(parent, options.HTTPTimeout)
	defer cancel()
	start := time.Now()
	hops := []HTTPHop{}
	base := &http.Transport{
		Proxy:                 nil, // Direct probe; system proxy is recorded separately.
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: options.HTTPTimeout,
		TLSClientConfig:       &tls.Config{RootCAs: options.RootCAs},
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
	data := HTTPData{Hops: hops, Transport: "direct"}
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
