package inspect

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

type TrustStatus struct {
	SystemTrusted bool   `json:"system_trusted"`
	Detail        string `json:"detail,omitempty"`
}

func ProcessScopedEnv(bundlePath, proxyURL string) map[string]string {
	env := map[string]string{
		"AGENTSNITCH_MANAGED_PROXY": "1",
		"AGENTSNITCH_INSPECT_MODE":  "process_scoped",
		"SSL_CERT_FILE":             bundlePath,
		"REQUESTS_CA_BUNDLE":        bundlePath,
		"CURL_CA_BUNDLE":            bundlePath,
		"GIT_SSL_CAINFO":            bundlePath,
		"NODE_EXTRA_CA_CERTS":       bundlePath,
		"npm_config_cafile":         bundlePath,
		"YARN_CA_FILE":              bundlePath,
	}
	if strings.TrimSpace(proxyURL) != "" {
		env["HTTP_PROXY"] = proxyURL
		env["HTTPS_PROXY"] = proxyURL
		env["ALL_PROXY"] = proxyURL
		env["NO_PROXY"] = "localhost,127.0.0.1,::1,.local"
	}
	return env
}

func SystemTrustStatus(cert *x509.Certificate) TrustStatus {
	if runtime.GOOS != "darwin" {
		return TrustStatus{SystemTrusted: false, Detail: "system trust detection is only supported on macOS"}
	}
	if cert == nil {
		return TrustStatus{SystemTrusted: false, Detail: "CA certificate missing"}
	}
	sha1Hex := CertSHA1Hex(cert)
	out, err := exec.Command("/usr/bin/security", "find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain").CombinedOutput()
	if err != nil {
		return TrustStatus{SystemTrusted: false, Detail: strings.TrimSpace(string(out))}
	}
	trusted := strings.Contains(strings.ToUpper(string(out)), sha1Hex)
	if trusted {
		return TrustStatus{SystemTrusted: true, Detail: "AgentSnitch CA fingerprint is present in the System keychain"}
	}
	return TrustStatus{SystemTrusted: false, Detail: "AgentSnitch CA fingerprint is not present in the System keychain"}
}

func InstallSystemTrust(caPath string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("system trust install is only supported on macOS")
	}
	script := fmt.Sprintf("do shell script %q with administrator privileges with prompt %q",
		shellQuote("/usr/bin/security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain "+shellArg(caPath)),
		"AgentSnitch wants to trust its local HTTPS inspection CA. Approve only if you enabled Advanced HTTPS Inspect Mode.")
	return exec.Command("/usr/bin/osascript", "-e", script).Run()
}

func RemoveSystemTrust(caPath string, cert *x509.Certificate) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("system trust removal is only supported on macOS")
	}
	if cert == nil {
		return fmt.Errorf("CA certificate missing")
	}
	sha1Hex := CertSHA1Hex(cert)
	command := fmt.Sprintf("/usr/bin/security remove-trusted-cert -d %s; /usr/bin/security delete-certificate -Z %s /Library/Keychains/System.keychain",
		shellArg(caPath), sha1Hex)
	script := fmt.Sprintf("do shell script %q with administrator privileges with prompt %q",
		shellQuote(command),
		"AgentSnitch wants to remove its HTTPS inspection CA from macOS trust.")
	return exec.Command("/usr/bin/osascript", "-e", script).Run()
}

func CertSHA1Hex(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func shellQuote(command string) string {
	return "/bin/sh -c " + "'" + strings.ReplaceAll(command, "'", "'\\''") + "'"
}

func shellArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
