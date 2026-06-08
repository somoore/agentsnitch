package inspect

import (
	"net"
	"net/netip"
	"strings"
)

func DestinationInScope(settings Settings, host string) bool {
	host = canonicalCertHost(host)
	if host == "" || bypassHost(host) {
		return false
	}
	for _, denied := range settings.HTTPSInspectNeverDomains {
		if domainMatches(host, denied) {
			return false
		}
	}
	if settings.HTTPSInspectDomainsMode == "selected" {
		for _, allowed := range settings.HTTPSInspectDomains {
			if domainMatches(host, allowed) {
				return true
			}
		}
		return false
	}
	return true
}

func bypassHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	switch host {
	case "", "localhost":
		return true
	}
	if strings.HasSuffix(host, ".local") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return true
		}
		return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
	}
	return false
}

func domainMatches(host, pattern string) bool {
	host = strings.Trim(strings.ToLower(host), ".")
	pattern = strings.Trim(strings.ToLower(pattern), ".")
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}
