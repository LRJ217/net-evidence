package diagnostic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type missingResolver struct{}

type fixedResolver struct{ addresses []net.IPAddr }

func (r fixedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.addresses, nil
}

func (missingResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestDNSFailureSkipsNetworkLayers(t *testing.T) {
	var progress []StepProgress
	result, err := Run(context.Background(), "missing.invalid", Options{
		Resolver: missingResolver{},
		OnStep:   func(step StepProgress) { progress = append(progress, step) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.DNS.Status != StatusFailure || result.DNS.Error.Kind != "dns_not_found" {
		t.Fatalf("wrong DNS result: %+v", result.DNS)
	}
	if result.TCP.Status != StatusSkipped || result.TLS.Status != StatusSkipped || result.HTTP.Status != StatusSkipped {
		t.Fatalf("dependent layers were not skipped: %+v", result)
	}
	if len(progress) != 5 || progress[0].ID != "environment" || progress[1].ID != "dns" ||
		progress[2].Status != StatusSkipped || progress[3].Status != StatusSkipped || progress[4].Status != StatusSkipped {
		t.Fatalf("unexpected progress sequence: %+v", progress)
	}
}

func TestHTTPRedirectEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result, err := Run(context.Background(), server.URL+"/start", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.DNS.Status != StatusSuccess || result.TCP.Status != StatusSuccess {
		t.Fatalf("expected DNS and TCP success: %+v %+v", result.DNS, result.TCP)
	}
	if result.TLS.Status != StatusSkipped || result.HTTP.Status != StatusSuccess {
		t.Fatalf("unexpected TLS/HTTP status: %+v %+v", result.TLS, result.HTTP)
	}
	if result.HTTP.Data.StatusCode != http.StatusNoContent || len(result.HTTP.Data.Hops) != 2 {
		t.Fatalf("redirect evidence missing: %+v", result.HTTP.Data)
	}
	if result.HTTP.Data.Hops[0].StatusCode != http.StatusFound ||
		result.HTTP.Data.Hops[1].StatusCode != http.StatusNoContent {
		t.Fatalf("wrong redirect chain: %+v", result.HTTP.Data.Hops)
	}
}

func TestTLSCertificateVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	trusted, err := Run(context.Background(), server.URL, Options{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	if trusted.TLS.Status != StatusSuccess || trusted.TLS.Data == nil || !trusted.TLS.Data.Verified {
		t.Fatalf("trusted certificate failed: %+v", trusted.TLS)
	}
	if trusted.HTTP.Status != StatusSuccess || trusted.HTTP.Data.StatusCode != http.StatusNoContent {
		t.Fatalf("HTTPS request failed: %+v", trusted.HTTP)
	}

	untrusted, err := Run(context.Background(), server.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if untrusted.TLS.Status != StatusFailure || untrusted.TLS.Error.Kind != "certificate_invalid" {
		t.Fatalf("untrusted certificate was accepted: %+v", untrusted.TLS)
	}
	if untrusted.TLS.Data == nil || untrusted.TLS.Data.CipherSuite == "" || !untrusted.TLS.Data.TimeValid {
		t.Fatalf("certificate evidence missing: %+v", untrusted.TLS.Data)
	}
	if untrusted.HTTP.Status != StatusSkipped {
		t.Fatalf("HTTP should not be sent after TLS failure: %+v", untrusted.HTTP)
	}
}

func TestTLSHostnameAndExpiryEvidence(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wrong.example"},
		DNSNames:     []string{"wrong.example"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKey}),
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()

	result, err := Run(context.Background(), server.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.TLS.Status != StatusFailure || result.TLS.Data == nil {
		t.Fatalf("expected certificate failure with evidence: %+v", result.TLS)
	}
	if result.TLS.Data.HostnameValid || result.TLS.Data.TimeValid {
		t.Fatalf("wrong hostname/expiry assessment: %+v", result.TLS.Data)
	}
	if result.HTTP.Status != StatusSkipped {
		t.Fatalf("HTTP was sent after invalid TLS: %+v", result.HTTP)
	}
}

func TestRefusedConnectionSkipsDependentLayers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	result, err := Run(context.Background(), "http://"+address, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.TCP.Status != StatusFailure || result.TCP.Error.Kind != "connection_refused" {
		t.Fatalf("wrong TCP classification: %+v", result.TCP)
	}
	if result.TLS.Status != StatusSkipped || result.HTTP.Status != StatusSkipped {
		t.Fatalf("dependent layers should be skipped: %+v %+v", result.TLS, result.HTTP)
	}
}

func TestTCPRecordsBothAddressFamilies(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	step := probeTCP(context.Background(), port, DNSData{IPv4: []string{"127.0.0.1"}, IPv6: []string{"::1"}}, time.Second)
	if step.Status != StatusSuccess || step.Data == nil || len(step.Data.Attempts) != 2 {
		t.Fatalf("missing per-family attempts: %+v", step)
	}
	if step.Data.Attempts[0].Family != "IPv4" || step.Data.Attempts[0].Status != StatusSuccess ||
		step.Data.Attempts[0].Address != listener.Addr().String() ||
		step.Data.Attempts[1].Family != "IPv6" || step.Data.Attempts[1].Status != StatusFailure {
		t.Fatalf("wrong address-family evidence: %+v", step.Data.Attempts)
	}
}

func TestTCPFailureKeepsAttemptedAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	listener.Close()
	step := probeTCP(context.Background(), port, DNSData{IPv4: []string{"127.0.0.1"}}, time.Second)
	if step.Status != StatusFailure || step.Data == nil || len(step.Data.Attempts) != 1 ||
		step.Data.Attempts[0].Address == "" || step.Data.Attempts[0].Error == nil {
		t.Fatalf("failed TCP attempt lost evidence: %+v", step)
	}
}

func TestHTTPUsesSuccessfulTCPAddress(t *testing.T) {
	var expectedHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != expectedHost {
			t.Errorf("unexpected host header: %q", r.Host)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	expectedHost = "probe.invalid:" + port
	result, err := Run(context.Background(), "http://probe.invalid:"+port, Options{
		Resolver: fixedResolver{addresses: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}},
	})
	if err != nil || result.TCP.Status != StatusSuccess || result.HTTP.Status != StatusSuccess {
		t.Fatalf("HTTP did not reuse the tested address: %+v %+v %v", result.TCP, result.HTTP, err)
	}
}

func TestHTTPTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	result, err := Run(context.Background(), server.URL, Options{HTTPTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if result.TCP.Status != StatusSuccess || result.HTTP.Status != StatusFailure {
		t.Fatalf("unexpected status: %+v %+v", result.TCP, result.HTTP)
	}
	if result.HTTP.Error.Kind != "timeout" {
		t.Fatalf("wrong timeout classification: %+v", result.HTTP.Error)
	}
}

func TestCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-started
		cancel()
	}()
	result, err := Run(ctx, server.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.HTTP.Status != StatusFailure || result.HTTP.Error.Kind != "canceled" {
		t.Fatalf("wrong cancellation result: %+v", result.HTTP)
	}
}

func TestRedirectLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer server.Close()
	result, err := Run(context.Background(), server.URL, Options{MaxRedirects: 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.HTTP.Status != StatusFailure || result.HTTP.Error.Kind != "redirect_limit" {
		t.Fatalf("wrong redirect classification: %+v", result.HTTP)
	}
	if len(result.HTTP.Data.Hops) != 3 {
		t.Fatalf("expected three observed responses, got %d", len(result.HTTP.Data.Hops))
	}
}

func TestDNSNotFoundClassification(t *testing.T) {
	err := &net.DNSError{Err: "no such host", Name: "missing.invalid", IsNotFound: true}
	if got := classifyError(err, "unknown"); got != "dns_not_found" {
		t.Fatalf("got %q", got)
	}
	if got := classifyError(fmt.Errorf("wrapped: %w", context.Canceled), "unknown"); got != "canceled" {
		t.Fatalf("got %q", got)
	}
}
