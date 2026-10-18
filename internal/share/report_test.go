package share

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
)

func TestSharedFormatsDoNotLeakRawEvidence(t *testing.T) {
	const secretPath = "C:\\Users\\alice\\private-folder"
	const secretToken = "top-secret-token-123"
	const secretProxy = "alice:password@192.168.1.20:8080"
	const secretMAC = "aa:bb:cc:dd:ee:ff"
	const secretHeader = "Cookie: session=top-secret-token-123; Authorization: Bearer top-secret-token-123"
	raw := diagnostic.Result{
		SchemaVersion: 1, ToolVersion: secretToken, StartedAt: time.Now().UTC(),
		Target: diagnostic.Target{
			Input:  "https://192.168.1.10/private/" + secretToken + "?token=" + secretToken,
			URL:    "https://192.168.1.10/private/" + secretToken + "?token=" + secretToken,
			Scheme: "https", Host: "192.168.1.10", Port: secretToken, Address: "192.168.1.10:443",
		},
		DNS: diagnostic.Step[diagnostic.DNSData]{ID: "dns", Status: diagnostic.StatusSuccess,
			Data: &diagnostic.DNSData{IPv4: []string{"192.168.1.10", "8.8.8.8"}, IPv6: []string{"fd00::1"}}},
		TCP: diagnostic.Step[diagnostic.TCPData]{ID: "tcp", Status: diagnostic.StatusSuccess,
			Data: &diagnostic.TCPData{ConnectedAddress: "192.168.1.10:443", Attempts: []diagnostic.TCPAttempt{
				{Family: "IPv4", Address: "192.168.1.10:443", Status: diagnostic.StatusSuccess},
				{Family: "IPv6", Address: "[fd00::1]:443", Status: diagnostic.StatusFailure,
					Error: &diagnostic.ProbeError{Kind: "timeout", Message: secretToken}},
			}}},
		TLS: diagnostic.Step[diagnostic.TLSData]{ID: "tls", Status: diagnostic.StatusFailure,
			Error: &diagnostic.ProbeError{Kind: "certificate_invalid", Message: secretPath},
			Data: &diagnostic.TLSData{Protocol: secretToken, CipherSuite: secretToken, VerifyError: secretPath,
				Certificate: diagnostic.CertificateData{Subject: "CN=" + secretToken, Issuer: secretPath, DNSNames: []string{secretToken}}}},
		HTTP: diagnostic.Step[diagnostic.HTTPData]{ID: "http", Status: diagnostic.StatusFailure,
			Error: &diagnostic.ProbeError{Kind: "timeout", Message: secretHeader + secretProxy},
			Data: &diagnostic.HTTPData{Transport: secretToken, FinalURL: "https://example.com/path/" + secretToken + "?auth=" + secretToken,
				Hops: []diagnostic.HTTPHop{{URL: "https://example.com/path/" + secretToken + "?auth=" + secretToken, StatusCode: 302}}}},
		ProxyHTTP: &diagnostic.Step[diagnostic.HTTPData]{ID: "proxy_http", Status: diagnostic.StatusFailure,
			Error: &diagnostic.ProbeError{Kind: "timeout", Message: secretProxy + secretToken},
			Data: &diagnostic.HTTPData{Transport: "system_proxy", FinalURL: "https://example.com/path/" + secretToken,
				Hops: []diagnostic.HTTPHop{{URL: "https://example.com/path/" + secretToken + "?auth=" + secretToken, StatusCode: 302}}}},
		Environment: diagnostic.Step[diagnostic.EnvironmentData]{ID: "environment", Status: diagnostic.StatusPartial,
			Error: &diagnostic.ProbeError{Kind: "unknown", Message: secretPath},
			Data: &diagnostic.EnvironmentData{ProxyError: secretPath,
				Proxy:      diagnostic.ProxyData{Enabled: true, Server: secretProxy, AutoConfigURL: "http://proxy/" + secretToken},
				Interfaces: []diagnostic.InterfaceData{{Name: "alice-ethernet", Addresses: []string{"192.168.1.100/24"}, MAC: secretMAC}}}},
	}
	before, _ := json.Marshal(raw)
	report := Build(raw)
	jsonData, err := RenderJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	htmlData, err := RenderHTML(report)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"json": jsonData, "html": htmlData, "issue": RenderIssue(report)} {
		for _, secret := range []string{secretPath, secretToken, secretProxy, secretMAC, secretHeader, "192.168.1.10", "192.168.1.100", "fd00::1", "alice-ethernet"} {
			if strings.Contains(string(data), secret) {
				t.Errorf("%s leaked %q", name, secret)
			}
		}
		if !strings.Contains(string(data), "certificate_time") && name == "json" {
			// Certificate validity is not set here, so the rule cites the TLS evidence.
			if !strings.Contains(string(data), "certificate_trust") {
				t.Errorf("%s missing TLS finding", name)
			}
		}
	}
	after, _ := json.Marshal(raw)
	if string(before) != string(after) {
		t.Fatal("Build mutated raw evidence")
	}
	hasTLSFinding := false
	for _, finding := range report.Findings {
		if len(finding.EvidenceIDs) > 0 && finding.EvidenceIDs[0] == "tls" {
			hasTLSFinding = true
		}
	}
	if !hasTLSFinding {
		t.Fatalf("missing evidence reference: %+v", report.Findings)
	}
	if report.Evidence.ProxyHTTP == nil || report.Evidence.ProxyHTTP.Data.Transport != "system_proxy" {
		t.Fatalf("proxy evidence was lost: %+v", report.Evidence.ProxyHTTP)
	}
	if len(report.Evidence.TCP.Data.Attempts) != 2 || report.Evidence.TCP.Data.Attempts[1].Family != "IPv6" ||
		report.Evidence.TCP.Data.Attempts[1].Address != "[ADDRESS_REDACTED]" {
		t.Fatalf("per-family TCP evidence was not safely projected: %+v", report.Evidence.TCP.Data)
	}
}

func TestAddressFamilyDifferenceFinding(t *testing.T) {
	r := diagnostic.Result{TCP: diagnostic.Step[diagnostic.TCPData]{Status: diagnostic.StatusSuccess,
		Data: &diagnostic.TCPData{Attempts: []diagnostic.TCPAttempt{
			{Family: "IPv4", Status: diagnostic.StatusSuccess},
			{Family: "IPv6", Status: diagnostic.StatusFailure, Error: &diagnostic.ProbeError{Kind: "network_unreachable"}},
		}}}}
	findings := Analyze(r)
	if len(findings) != 1 || findings[0].ID != "address_family_difference" {
		t.Fatalf("family difference was omitted: %+v", findings)
	}
}

func TestRuleEvidenceAndStatus(t *testing.T) {
	tests := []struct {
		name   string
		result diagnostic.Result
		want   string
		id     string
	}{
		{"dns", diagnostic.Result{DNS: diagnostic.Step[diagnostic.DNSData]{Status: diagnostic.StatusFailure}}, "dns_failure", "dns"},
		{"refused", diagnostic.Result{TCP: diagnostic.Step[diagnostic.TCPData]{Status: diagnostic.StatusFailure, Error: &diagnostic.ProbeError{Kind: "connection_refused"}}}, "tcp_refused", "tcp"},
		{"expired", diagnostic.Result{TLS: diagnostic.Step[diagnostic.TLSData]{Status: diagnostic.StatusFailure, Error: &diagnostic.ProbeError{Kind: "certificate_invalid"}, Data: &diagnostic.TLSData{HostnameValid: true}}}, "certificate_time", "tls"},
		{"server", diagnostic.Result{HTTP: diagnostic.Step[diagnostic.HTTPData]{Status: diagnostic.StatusSuccess, Data: &diagnostic.HTTPData{StatusCode: 503}}}, "http_server_error", "http"},
		{"clear", diagnostic.Result{}, "no_obvious_failure", "dns"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := Analyze(tc.result)
			if len(findings) == 0 || findings[0].ID != tc.want || findings[0].EvidenceIDs[0] != tc.id {
				t.Fatalf("findings = %+v", findings)
			}
		})
	}
}

func TestHTMLTemplateEscapesReportContent(t *testing.T) {
	report := Build(diagnostic.Result{})
	report.PrivacyNote = "<script>alert(1)</script>"
	data, err := RenderHTML(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "<script>alert(1)</script>") {
		t.Fatal("HTML contains executable content")
	}
}

func TestProxyInferenceOnlyForRemoteTarget(t *testing.T) {
	r := diagnostic.Result{
		Target:      diagnostic.Target{Host: "example.com"},
		TCP:         diagnostic.Step[diagnostic.TCPData]{Status: diagnostic.StatusFailure},
		Environment: diagnostic.Step[diagnostic.EnvironmentData]{Data: &diagnostic.EnvironmentData{Proxy: diagnostic.ProxyData{Enabled: true}}},
	}
	findings := Analyze(r)
	if len(findings) != 2 || findings[1].ID != "proxy_path" {
		t.Fatalf("missing proxy caveat: %+v", findings)
	}
	r.Target.Host = "127.0.0.1"
	if findings = Analyze(r); len(findings) != 1 {
		t.Fatalf("loopback should not imply proxy path: %+v", findings)
	}
}

func TestProxySuccessExplainsDirectFailure(t *testing.T) {
	r := diagnostic.Result{
		Target: diagnostic.Target{Host: "example.com"},
		TCP:    diagnostic.Step[diagnostic.TCPData]{Status: diagnostic.StatusFailure},
		ProxyHTTP: &diagnostic.Step[diagnostic.HTTPData]{Status: diagnostic.StatusSuccess,
			Data: &diagnostic.HTTPData{StatusCode: 200, Transport: "system_proxy"}},
	}
	findings := Analyze(r)
	if len(findings) != 2 || findings[1].ID != "proxy_path_confirmed" || findings[1].EvidenceIDs[0] != "proxy_http" {
		t.Fatalf("proxy path was not explained: %+v", findings)
	}
}

func TestCancellationIsNotReportedAsNetworkFailure(t *testing.T) {
	r := diagnostic.Result{
		Target: diagnostic.Target{Host: "example.com"},
		HTTP: diagnostic.Step[diagnostic.HTTPData]{Status: diagnostic.StatusFailure,
			Error: &diagnostic.ProbeError{Kind: "canceled"}},
	}
	findings := Analyze(r)
	if len(findings) != 1 || findings[0].ID != "diagnosis_canceled" {
		t.Fatalf("cancel was misinterpreted: %+v", findings)
	}
	r.ProxyHTTP = &diagnostic.Step[diagnostic.HTTPData]{Status: diagnostic.StatusSuccess,
		Data: &diagnostic.HTTPData{StatusCode: 200, Transport: "system_proxy"}}
	findings = Analyze(r)
	for _, finding := range findings {
		if finding.ID == "proxy_path_confirmed" {
			t.Fatalf("cancel was treated as direct failure: %+v", findings)
		}
	}
}
