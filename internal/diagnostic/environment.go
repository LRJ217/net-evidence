package diagnostic

import (
	"net"
	"os"
	"sort"
	"time"
)

func probeEnvironment() Step[EnvironmentData] {
	step := Step[EnvironmentData]{ID: "environment"}
	start := time.Now()
	proxy, proxyErr := systemProxy()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if value, ok := os.LookupEnv(name); ok && value != "" {
			proxy.EnvPresent = true
			break
		}
	}
	data := EnvironmentData{Proxy: proxy, Interfaces: []InterfaceData{}}
	if proxyErr != nil {
		data.ProxyError = proxyErr.Error()
	}
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, item := range interfaces {
			if item.Flags&net.FlagUp == 0 {
				continue
			}
			entry := InterfaceData{Name: item.Name, MAC: item.HardwareAddr.String(), Addresses: []string{}}
			addresses, addressErr := item.Addrs()
			if addressErr != nil {
				continue
			}
			for _, address := range addresses {
				entry.Addresses = append(entry.Addresses, address.String())
			}
			sort.Strings(entry.Addresses)
			data.Interfaces = append(data.Interfaces, entry)
		}
		sort.Slice(data.Interfaces, func(i, j int) bool { return data.Interfaces[i].Name < data.Interfaces[j].Name })
	}
	step.DurationMs = time.Since(start).Milliseconds()
	step.Data = &data
	if err != nil {
		step.Status = StatusFailure
		step.Error = probeError(err)
	} else if proxyErr != nil {
		step.Status = StatusPartial
	} else {
		step.Status = StatusSuccess
	}
	return step
}
