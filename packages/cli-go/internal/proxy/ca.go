package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sort"
	"sync"
	"time"
)

// authority is a certificate authority for one session. Its key lives only
// in memory. Name constraints limit it to the hosts in active policies, so
// a leaked CA certificate cannot vouch for any other site (threat model
// T-29). It is never installed in a system trust store.
type authority struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	der     []byte
	domains []string

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func newAuthority(domains []string) (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	sorted := append([]string(nil), domains...)
	sort.Strings(sorted)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: "secrethandoff session proxy"},
		NotBefore:                   now.Add(-time.Minute),
		NotAfter:                    now.Add(24 * time.Hour),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         sorted,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{key: key, cert: cert, der: der, domains: sorted, leaves: map[string]*tls.Certificate{}}, nil
}

// PEM returns the CA certificate, never its key.
func (a *authority) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.der})
}

// leaf returns a certificate for exactly one host name.
func (a *authority) leaf(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.leaves[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     a.cert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, a.der}, PrivateKey: key}
	a.leaves[host] = c
	return c, nil
}
