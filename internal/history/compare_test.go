package history

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
)

func TestCompareEnvironmentOnlyExposesChangeFlags(t *testing.T) {
	left := Record{Result: sampleResult("https://example.com", diagnostic.StatusSuccess, 1)}
	right := Record{Result: sampleResult("https://example.com", diagnostic.StatusSuccess, 1)}
	left.Result.Environment.Data = &diagnostic.EnvironmentData{
		Proxy:      diagnostic.ProxyData{Enabled: true, Server: "secret-proxy-a:8080", BypassList: "*.private-a.test"},
		Interfaces: []diagnostic.InterfaceData{{Name: "private-vpn-a", Addresses: []string{"10.0.0.1/24"}}},
	}
	right.Result.Environment.Data = &diagnostic.EnvironmentData{
		Proxy:      diagnostic.ProxyData{Enabled: true, Server: "secret-proxy-b:8080", BypassList: "*.private-a.test"},
		Interfaces: []diagnostic.InterfaceData{{Name: "private-vpn-b", Addresses: []string{"10.0.0.2/24"}}},
	}
	left.Result.DNS.Data = &diagnostic.DNSData{IPv4: []string{"192.0.2.1"}}
	right.Result.DNS.Data = &diagnostic.DNSData{IPv4: []string{"192.0.2.2"}}
	comparison := Compare(left, right)
	diff := comparison.Environment
	if !diff.Available || !diff.ProxyServerChanged || !diff.NetworkInterfacesChanged ||
		!diff.DNSAnswersAvailable || !diff.DNSAnswersChanged || diff.ProxyEnabledChanged || diff.ProxyBypassChanged {
		t.Fatalf("wrong environment diff: %+v", diff)
	}
	encoded, err := json.Marshal(comparison)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-proxy", "private-vpn", "10.0.0.", "192.0.2."} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("comparison leaked %q: %s", secret, encoded)
		}
	}
}

func TestCompareDoesNotTreatDifferentTargetsAsDNSChange(t *testing.T) {
	left := Record{Result: sampleResult("https://one.example", diagnostic.StatusSuccess, 1)}
	right := Record{Result: sampleResult("https://two.example", diagnostic.StatusSuccess, 1)}
	left.Result.Target.Host = "one.example"
	right.Result.Target.Host = "two.example"
	left.Result.DNS.Data = &diagnostic.DNSData{IPv4: []string{"192.0.2.1"}}
	right.Result.DNS.Data = &diagnostic.DNSData{IPv4: []string{"192.0.2.2"}}
	diff := Compare(left, right).Environment
	if diff.DNSAnswersAvailable || diff.DNSAnswersChanged {
		t.Fatalf("different domains must not be compared as DNS changes: %+v", diff)
	}
}
