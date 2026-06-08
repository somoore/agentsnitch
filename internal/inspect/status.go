package inspect

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

type Status struct {
	Enabled        bool              `json:"enabled"`
	Proxy          ProxyStatus       `json:"proxy"`
	CA             CAInfo            `json:"ca"`
	Trust          TrustStatus       `json:"trust"`
	TrustMode      string            `json:"trust_mode"`
	PayloadMode    string            `json:"payload_mode"`
	Retention      string            `json:"retention"`
	ProcessEnv     map[string]string `json:"process_env,omitempty"`
	Warnings       []string          `json:"warnings"`
	LastInspection string            `json:"last_inspection,omitempty"`
}

func CurrentStatus(proxy ProxyStatus) Status {
	settings, _ := LoadSettings()
	paths := DefaultPaths()
	manager := NewCertManager(paths)
	caInfo, caErr := manager.Info()
	cert, _ := loadCertificate(paths.CAPath)
	trust := SystemTrustStatus(cert)
	status := Status{
		Enabled:     settings.HTTPSInspectEnabled,
		Proxy:       proxy,
		CA:          caInfo,
		Trust:       trust,
		TrustMode:   settings.TrustMode(trust.SystemTrusted),
		PayloadMode: settings.PayloadMode(),
		Retention:   settings.HTTPSInspectFullRetention,
	}
	if caErr != nil && !errors.Is(caErr, os.ErrNotExist) {
		status.Warnings = append(status.Warnings, "CA state unreadable: "+caErr.Error())
	}
	if settings.HTTPSInspectEnabled && !caInfo.Present {
		status.Warnings = append(status.Warnings, "Inspect Mode enabled but local CA is missing.")
	}
	if caInfo.Present {
		if err := CheckKeyPermissions(paths); err != nil {
			status.Warnings = append(status.Warnings, err.Error())
		}
	}
	if !settings.HTTPSInspectEnabled && trust.SystemTrusted {
		status.Warnings = append(status.Warnings, "System trust is installed while HTTPS Inspect Mode is disabled.")
	}
	if settings.HTTPSInspectEnabled && !proxy.Listening {
		status.Warnings = append(status.Warnings, "Inspect Mode enabled but managed proxy is unavailable.")
	}
	if settings.HTTPSInspectCaptureFull && settings.HTTPSInspectFullRetention == FullPayloadManual {
		status.Warnings = append(status.Warnings, "Full payload capture is enabled with manual retention.")
	}
	return status
}

func loadCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("certificate PEM is invalid")
	}
	return x509.ParseCertificate(block.Bytes)
}

func PurgeData(paths Paths) error {
	if err := os.RemoveAll(paths.DataDir); err != nil {
		return err
	}
	return os.MkdirAll(paths.DataDir, 0o700)
}
