package inspect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const caCommonName = "AgentSnitch Local HTTPS Inspection CA"

type CAInfo struct {
	Present     bool      `json:"present"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	CAPath      string    `json:"ca_path,omitempty"`
	KeyPath     string    `json:"key_path,omitempty"`
}

type CertManager struct {
	paths Paths
	mu    sync.Mutex
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
	leaf  map[string]*tls.Certificate
}

func NewCertManager(paths Paths) *CertManager {
	return &CertManager{paths: paths, leaf: make(map[string]*tls.Certificate)}
}

func (m *CertManager) EnsureCA() (CAInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := EnsureDirs(m.paths); err != nil {
		return CAInfo{}, err
	}
	if err := m.loadCALocked(); err == nil {
		return m.infoLocked(), m.writeBundleLocked()
	}
	ca, key, certPEM, keyPEM, err := generateCA()
	if err != nil {
		return CAInfo{}, err
	}
	if err := os.WriteFile(m.paths.CAPath, certPEM, 0o644); err != nil {
		return CAInfo{}, err
	}
	if err := writePrivateFile(m.paths.KeyPath, keyPEM); err != nil {
		return CAInfo{}, err
	}
	m.ca = ca
	m.key = key
	m.leaf = make(map[string]*tls.Certificate)
	return m.infoLocked(), m.writeBundleLocked()
}

func (m *CertManager) Info() (CAInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.loadCALocked(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CAInfo{Present: false, CAPath: m.paths.CAPath, KeyPath: m.paths.KeyPath}, nil
		}
		return CAInfo{Present: false, CAPath: m.paths.CAPath, KeyPath: m.paths.KeyPath}, err
	}
	return m.infoLocked(), nil
}

func (m *CertManager) DeleteCA() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ca = nil
	m.key = nil
	m.leaf = make(map[string]*tls.Certificate)
	for _, path := range []string{m.paths.CAPath, m.paths.KeyPath, m.paths.BundlePath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.RemoveAll(m.paths.LeafDir)
}

func (m *CertManager) RotateCA() (CAInfo, error) {
	if err := m.DeleteCA(); err != nil {
		return CAInfo{}, err
	}
	return m.EnsureCA()
}

func (m *CertManager) BundlePath() (string, error) {
	if _, err := m.EnsureCA(); err != nil {
		return "", err
	}
	return m.paths.BundlePath, nil
}

func (m *CertManager) LeafCertificate(host string) (*tls.Certificate, error) {
	host = canonicalCertHost(host)
	if host == "" {
		return nil, errors.New("empty leaf host")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cert, ok := m.leaf[host]; ok {
		return cert, nil
	}
	if err := m.loadCALocked(); err != nil {
		return nil, err
	}
	cert, err := m.generateLeafLocked(host)
	if err != nil {
		return nil, err
	}
	m.leaf[host] = cert
	return cert, nil
}

func (m *CertManager) loadCALocked() error {
	if m.ca != nil && m.key != nil {
		return nil
	}
	certPEM, err := os.ReadFile(m.paths.CAPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(m.paths.KeyPath)
	if err != nil {
		return err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("CA certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || !strings.Contains(keyBlock.Type, "PRIVATE KEY") {
		return errors.New("CA private key PEM is invalid")
	}
	parsed, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	m.ca = cert
	m.key = parsed
	return nil
}

func (m *CertManager) infoLocked() CAInfo {
	if m.ca == nil {
		return CAInfo{Present: false, CAPath: m.paths.CAPath, KeyPath: m.paths.KeyPath}
	}
	return CAInfo{
		Present:     true,
		Fingerprint: Fingerprint(m.ca),
		Subject:     m.ca.Subject.String(),
		NotBefore:   m.ca.NotBefore,
		NotAfter:    m.ca.NotAfter,
		CAPath:      m.paths.CAPath,
		KeyPath:     m.paths.KeyPath,
	}
}

func (m *CertManager) writeBundleLocked() error {
	raw, err := os.ReadFile(m.paths.CAPath)
	if err != nil {
		return err
	}
	return os.WriteFile(m.paths.BundlePath, raw, 0o644)
}

func (m *CertManager) generateLeafLocked(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca, &key.PublicKey, m.key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{"AgentSnitch"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return cert, key,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		nil
}

func writePrivateFile(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func canonicalCertHost(host string) string {
	host = strings.TrimSpace(host)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.Trim(strings.ToLower(host), "[]")
}

func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return "SHA256:" + strings.ToUpper(hex.EncodeToString(sum[:]))
}

func SHA1Hex(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func CheckKeyPermissions(paths Paths) error {
	info, err := os.Stat(paths.KeyPath)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("private key permissions are %o, want 0600", info.Mode().Perm())
	}
	parent, err := os.Stat(filepath.Dir(paths.KeyPath))
	if err != nil {
		return err
	}
	if parent.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("private key parent directory is world-writable: %o", parent.Mode().Perm())
	}
	return nil
}
