//go:build windows

package diagnostic

import "golang.org/x/sys/windows/registry"

func systemProxy() (ProxyData, error) {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return ProxyData{}, err
	}
	defer key.Close()
	data := ProxyData{}
	if value, _, err := key.GetIntegerValue("ProxyEnable"); err == nil {
		data.Enabled = value != 0
	}
	if value, _, err := key.GetStringValue("ProxyServer"); err == nil {
		data.Server = value
	}
	if value, _, err := key.GetStringValue("AutoConfigURL"); err == nil {
		data.AutoConfigURL = value
		if value != "" {
			data.Enabled = true
		}
	}
	return data, nil
}
