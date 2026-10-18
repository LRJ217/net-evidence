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
