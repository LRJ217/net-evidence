//go:build !windows

package diagnostic

import "errors"

func systemProxy() (ProxyData, error) {
	return ProxyData{}, errors.New("system proxy inspection is currently Windows-only")
}
