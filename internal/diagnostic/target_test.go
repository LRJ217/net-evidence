package diagnostic

import "testing"

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		input  string
		url    string
		host   string
		scheme string
	}{
		{"example.com", "https://example.com:443/", "example.com", "https"},
		{"EXAMPLE.com:80", "http://example.com:80/", "example.com", "http"},
		{"localhost:8443", "http://localhost:8443/", "localhost", "http"},
		{"[::1]:443", "https://[::1]:443/", "::1", "https"},
		{"::1", "https://[::1]:443/", "::1", "https"},
		{"https://example.com/path?q=1#ignored", "https://example.com:443/path?q=1", "example.com", "https"},
		{"https://bücher.de", "https://xn--bcher-kva.de:443/", "xn--bcher-kva.de", "https"},
		{"HTTPS://EXAMPLE.COM", "https://example.com:443/", "example.com", "https"},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := NormalizeTarget(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if got.URL != test.url || got.Host != test.host || got.Scheme != test.scheme {
				t.Fatalf("NormalizeTarget(%q) = %#v", test.input, got)
			}
		})
	}
}

func TestNormalizeTargetRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{
		"", " ", "example.com/path", "ftp://example.com",
		"http://user:pass@example.com", "http://example.com:0",
		"example.com:65536", "http://bad..example", "http://[fe80::1%25eth0]",
		"example.com:abc", "example.com:", "http://example.com/\nheader",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := NormalizeTarget(input); err == nil {
				t.Fatalf("accepted invalid target %q", input)
			}
		})
	}
}
