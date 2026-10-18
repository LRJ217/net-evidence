package diagnostic

import (
	"context"
	"crypto/x509"
	"net"
	"time"
)

type Status string

const (
	StatusSuccess Status = "success"
	StatusFailure Status = "failure"
	StatusSkipped Status = "skipped"
	StatusPartial Status = "partial"
)

type ProbeError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// Step has a stable ID so later rules can cite the exact evidence used.
type Step[T any] struct {
	ID         string      `json:"id"`
	Status     Status      `json:"status"`
	DurationMs int64       `json:"duration_ms"`
	Data       *T          `json:"data,omitempty"`
	Error      *ProbeError `json:"error,omitempty"`
	Reason     string      `json:"reason,omitempty"`
}

type DNSData struct {
	IPv4         []string      `json:"ipv4"`
	IPv6         []string      `json:"ipv6"`
	AddressKinds *AddressKinds `json:"address_kinds,omitempty"`
}

// AddressKinds is a coarse summary for shared reports. "Other" does not
// imply that an address is publicly reachable.
type AddressKinds struct {
	Private   int `json:"private,omitempty"`
	Loopback  int `json:"loopback,omitempty"`
	LinkLocal int `json:"link_local,omitempty"`
	Other     int `json:"other,omitempty"`
}

type TCPData struct {
	ConnectedAddress string       `json:"connected_address,omitempty"`
	Attempts         []TCPAttempt `json:"attempts,omitempty"`
}

type TCPAttempt struct {
	Family     string      `json:"family"`
	Address    string      `json:"address"`
	Status     Status      `json:"status"`
	DurationMs int64       `json:"duration_ms"`
	Error      *ProbeError `json:"error,omitempty"`
}

type CertificateData struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dns_names"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

type TLSData struct {
	Protocol      string          `json:"protocol"`
	CipherSuite   string          `json:"cipher_suite"`
	HandshakeMs   int64           `json:"handshake_ms"`
	Certificate   CertificateData `json:"certificate"`
	HostnameValid bool            `json:"hostname_valid"`
	TimeValid     bool            `json:"time_valid"`
	Verified      bool            `json:"verified"`
	VerifyError   string          `json:"verify_error,omitempty"`
}

type HTTPHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	DurationMs int64  `json:"duration_ms"`
}

type HTTPData struct {
	StatusCode int       `json:"status_code"`
	FinalURL   string    `json:"final_url"`
	Hops       []HTTPHop `json:"hops"`
	Transport  string    `json:"transport"`
}

type ProxyData struct {
	Enabled       bool   `json:"enabled"`
	Server        string `json:"server,omitempty"`
	BypassList    string `json:"bypass_list,omitempty"`
	AutoConfigURL string `json:"auto_config_url,omitempty"`
	EnvPresent    bool   `json:"env_present"`
}

type InterfaceData struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	MAC       string   `json:"mac,omitempty"`
}

type EnvironmentData struct {
	Proxy      ProxyData       `json:"proxy"`
	Interfaces []InterfaceData `json:"interfaces"`
	ProxyError string          `json:"proxy_error,omitempty"`
}

type Result struct {
	SchemaVersion int                   `json:"schema_version"`
	ToolVersion   string                `json:"tool_version"`
	StartedAt     time.Time             `json:"started_at"`
	DurationMs    int64                 `json:"duration_ms"`
	Target        Target                `json:"target"`
	DNS           Step[DNSData]         `json:"dns"`
	TCP           Step[TCPData]         `json:"tcp"`
	TLS           Step[TLSData]         `json:"tls"`
	HTTP          Step[HTTPData]        `json:"http"`
	ProxyHTTP     *Step[HTTPData]       `json:"proxy_http,omitempty"`
	Environment   Step[EnvironmentData] `json:"environment"`
}

type Options struct {
	TotalTimeout time.Duration
	DNSTimeout   time.Duration
	TCPTimeout   time.Duration
	TLSTimeout   time.Duration
	HTTPTimeout  time.Duration
	ProxyTimeout time.Duration
	// ProbeSystemProxy enables an independent request through a manual proxy.
	// The CLI leaves it off; the desktop enables it.
	ProbeSystemProxy bool
	// ProxyConfig allows a deterministic proxy configuration in local tests.
	ProxyConfig  *ProxyData
	MaxRedirects int
	// RootCAs is useful for local integration tests and private PKI.
	RootCAs *x509.CertPool
	// Resolver permits deterministic DNS tests and custom local resolution.
	Resolver IPResolver
	// OnStep receives a small, non-sensitive update after each layer finishes.
	OnStep func(StepProgress)
}

type StepProgress struct {
	ID         string `json:"id"`
	Status     Status `json:"status"`
	DurationMs int64  `json:"duration_ms"`
}

type IPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

func (o Options) withDefaults() Options {
	if o.TotalTimeout <= 0 {
		o.TotalTimeout = 20 * time.Second
	}
	if o.DNSTimeout <= 0 {
		o.DNSTimeout = 3 * time.Second
	}
	if o.TCPTimeout <= 0 {
		o.TCPTimeout = 3 * time.Second
	}
	if o.TLSTimeout <= 0 {
		o.TLSTimeout = 5 * time.Second
	}
	if o.HTTPTimeout <= 0 {
		o.HTTPTimeout = 8 * time.Second
	}
	if o.ProxyTimeout <= 0 {
		o.ProxyTimeout = 5 * time.Second
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = 5
	}
	return o
}
