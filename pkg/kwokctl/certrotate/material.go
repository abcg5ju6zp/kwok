/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certrotate

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"sigs.k8s.io/kwok/pkg/kwokctl/pki"
	"sigs.k8s.io/kwok/pkg/utils/sets"
)

// Profile selects the set of trust material a runtime consumes.
type Profile string

const (
	// ProfileCore is the material used by the binary and compose runtimes: a
	// single root CA plus one admin credential that is used both as the API
	// server serving certificate and as the client credential.
	ProfileCore Profile = "core"
	// ProfileKind is the full kubeadm compatible material used by the kind
	// runtime, including its separate etcd and front proxy trust chains.
	ProfileKind Profile = "kind"
)

// MaterialFile describes a single file of a certificate profile.
type MaterialFile struct {
	// Path is the path relative to the PKI directory.
	Path string
	// Public is true for certificates and public keys.
	Public bool
}

var (
	caFiles = []string{
		"ca.crt", "ca.key",
	}
	adminFiles = []string{
		"admin.crt", "admin.key",
	}
	// kindEtcdFiles are published during the etcd stage of a kind rotation.
	kindEtcdFiles = []string{
		"etcd/ca.crt", "etcd/ca.key",
		"etcd/server.crt", "etcd/server.key",
		"etcd/peer.crt", "etcd/peer.key",
		"etcd/healthcheck-client.crt", "etcd/healthcheck-client.key",
		"apiserver-etcd-client.crt", "apiserver-etcd-client.key",
	}
	// kindMainFiles are published during the API server stage of a kind
	// rotation.
	kindMainFiles = append([]string{
		"admin.crt", "admin.key",
		"apiserver.crt", "apiserver.key",
		"apiserver-kubelet-client.crt", "apiserver-kubelet-client.key",
		"front-proxy-ca.crt", "front-proxy-ca.key",
		"front-proxy-client.crt", "front-proxy-client.key",
		"sa.key", "sa.pub",
	}, caFiles...)
)

// etcdFiles returns the material files that must be published at the etcd
// stage for the profile.
func etcdFiles(profile Profile) []string {
	if profile == ProfileKind {
		return append([]string{}, kindEtcdFiles...)
	}
	return nil
}

// mainFiles returns the material files that must be published at the API
// server stage for the profile.
func mainFiles(profile Profile) []string {
	if profile == ProfileKind {
		return append([]string{}, kindMainFiles...)
	}
	return append(append([]string{}, caFiles...), adminFiles...)
}

// allFiles returns every file that must be present in a validated generation.
func allFiles(profile Profile) []string {
	return append(etcdFiles(profile), mainFiles(profile)...)
}

// GenerateMaterial generates the complete new trust material for a rotation
// into dst, in isolation from the live PKI directory. SANs of existing leaf
// certificates are inherited so the new material is a drop-in replacement.
func GenerateMaterial(_ context.Context, dst string, profile Profile, clusterName string, extraSANs []string, livePkiDir string) error {
	now := time.Now()
	notBefore := now.Add(-24 * time.Hour).UTC()
	notAfter := now.Add(pki.CertificateValidity).UTC()

	if err := os.MkdirAll(filepath.Join(dst, "etcd"), 0o755); err != nil {
		return fmt.Errorf("failed to create isolated pki dir: %w", err)
	}

	// Root CA.
	caCert, caKey, err := pki.GenerateCA(pki.DefaultCN, notBefore, notAfter)
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}
	if err := pki.WriteCertAndKey(dst, "ca", caCert, caKey); err != nil {
		return fmt.Errorf("failed to write CA: %w", err)
	}

	// Admin / shared component credential.
	adminSANs := append([]string{}, pki.DefaultAltNames...)
	adminSANs = append(adminSANs, extraSANs...)
	if dns, ips, err := readCertAltNames(filepath.Join(livePkiDir, "admin.crt")); err == nil {
		adminSANs = append(adminSANs, dns...)
		adminSANs = append(adminSANs, ips...)
	}
	adminCert, adminKey, err := pki.GenerateSignCert(pki.DefaultUser, caCert, caKey, notBefore, notAfter, pki.DefaultGroups, adminSANs)
	if err != nil {
		return fmt.Errorf("failed to generate admin credential: %w", err)
	}
	if err := pki.WriteCertAndKey(dst, "admin", adminCert, adminKey); err != nil {
		return fmt.Errorf("failed to write admin credential: %w", err)
	}

	if profile != ProfileKind {
		return nil
	}

	if err := generateKindMaterial(dst, clusterName, notBefore, notAfter, caCert, caKey, livePkiDir); err != nil {
		return err
	}
	return nil
}

func generateKindMaterial(dst, clusterName string, notBefore, notAfter time.Time, caCert *x509.Certificate, caKey crypto.Signer, livePkiDir string) error {
	nodeName := clusterName + "-control-plane"

	// API server serving credential.
	apiserverSANs := append([]string{}, pki.DefaultAltNames...)
	apiserverSANs = append(apiserverSANs, clusterName, nodeName)
	if dns, ips, err := readCertAltNames(filepath.Join(livePkiDir, "apiserver.crt")); err == nil {
		apiserverSANs = append(apiserverSANs, dns...)
		apiserverSANs = append(apiserverSANs, ips...)
	}
	if err := writeSignedCert(dst, "apiserver", "kube-apiserver", nil, apiserverSANs, caCert, caKey, notBefore, notAfter); err != nil {
		return err
	}

	// kube-apiserver -> kubelet client credential.
	if err := writeSignedCert(dst, "apiserver-kubelet-client", "kube-apiserver-kubelet-client", []string{"system:masters"}, nil, caCert, caKey, notBefore, notAfter); err != nil {
		return err
	}

	// Front proxy CA and client credential.
	frontProxyCACert, frontProxyCAKey, err := pki.GenerateCA("front-proxy-ca", notBefore, notAfter)
	if err != nil {
		return fmt.Errorf("failed to generate front proxy CA: %w", err)
	}
	if err := pki.WriteCertAndKey(dst, "front-proxy-ca", frontProxyCACert, frontProxyCAKey); err != nil {
		return fmt.Errorf("failed to write front proxy CA: %w", err)
	}
	if err := writeSignedCert(dst, "front-proxy-client", "front-proxy-client", nil, nil, frontProxyCACert, frontProxyCAKey, notBefore, notAfter); err != nil {
		return err
	}

	// Service account key pair.
	if err := writeServiceAccountKey(dst); err != nil {
		return err
	}

	// etcd CA and its leaf credentials.
	etcdCACert, etcdCAKey, err := pki.GenerateCA("etcd-ca", notBefore, notAfter)
	if err != nil {
		return fmt.Errorf("failed to generate etcd CA: %w", err)
	}
	if err := pki.WriteCertAndKey(filepath.Join(dst, "etcd"), "ca", etcdCACert, etcdCAKey); err != nil {
		return fmt.Errorf("failed to write etcd CA: %w", err)
	}

	serverSANs := []string{"localhost", nodeName}
	serverSANs = append(serverSANs, "127.0.0.1")
	if dns, ips, err := readCertAltNames(filepath.Join(livePkiDir, "etcd", "server.crt")); err == nil {
		serverSANs = append(serverSANs, dns...)
		serverSANs = append(serverSANs, ips...)
	}
	if err := writeSignedCert(filepath.Join(dst, "etcd"), "server", "kube-etcd-server", nil, serverSANs, etcdCACert, etcdCAKey, notBefore, notAfter); err != nil {
		return err
	}

	peerSANs := []string{nodeName, "127.0.0.1"}
	if dns, ips, err := readCertAltNames(filepath.Join(livePkiDir, "etcd", "peer.crt")); err == nil {
		peerSANs = append(peerSANs, dns...)
		peerSANs = append(peerSANs, ips...)
	}
	if err := writeSignedCert(filepath.Join(dst, "etcd"), "peer", "kube-etcd-peer", nil, peerSANs, etcdCACert, etcdCAKey, notBefore, notAfter); err != nil {
		return err
	}

	if err := writeSignedCert(filepath.Join(dst, "etcd"), "healthcheck-client", "kube-apiserver-healthcheck", []string{"system:masters"}, nil, etcdCACert, etcdCAKey, notBefore, notAfter); err != nil {
		return err
	}

	if err := writeSignedCert(dst, "apiserver-etcd-client", "kube-apiserver-etcd-client", []string{"system:masters"}, nil, etcdCACert, etcdCAKey, notBefore, notAfter); err != nil {
		return err
	}

	return nil
}

func writeSignedCert(dir, name, cn string, groups, sans []string, caCert *x509.Certificate, caKey crypto.Signer, notBefore, notAfter time.Time) error {
	cert, key, err := pki.GenerateSignCert(cn, caCert, caKey, notBefore, notAfter, groups, sans)
	if err != nil {
		return fmt.Errorf("failed to generate %s certificate: %w", name, err)
	}
	if err := pki.WriteCertAndKey(dir, name, cert, key); err != nil {
		return fmt.Errorf("failed to write %s certificate: %w", name, err)
	}
	return nil
}

func writeServiceAccountKey(dir string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate service account key: %w", err)
	}
	keyPEM, err := pki.EncodePrivateKeyToPEM(key)
	if err != nil {
		return fmt.Errorf("failed to encode service account key: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "sa.key"), keyPEM); err != nil {
		return fmt.Errorf("failed to write service account key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal service account public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := writeFileAtomic(filepath.Join(dir, "sa.pub"), pubPEM); err != nil {
		return fmt.Errorf("failed to write service account public key: %w", err)
	}
	return nil
}

func readCertAltNames(path string) (dnsNames []string, ips []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return append([]string{}, cert.DNSNames...), ips, nil
}

type certKeyPair struct {
	base string
	cert *x509.Certificate
	key  crypto.Signer
}

func readPairAt(dir, base string) (*certKeyPair, error) {
	cert, err := readCertificateFile(filepath.Join(dir, base+".crt"))
	if err != nil {
		return nil, err
	}
	key, err := readKeyFile(filepath.Join(dir, base+".key"))
	if err != nil {
		return nil, err
	}
	return &certKeyPair{base: base, cert: cert, key: key}, nil
}

func readCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate %s: %w", path, err)
	}
	return cert, nil
}

func readKeyFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode key PEM in %s", path)
	}
	switch block.Type {
	case pki.RSAPrivateKeyBlockType:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	case pki.ECPrivateKeyBlockType:
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q in %s", block.Type, path)
	}
}

// minNewCertificateValidity is the minimum lifetime a freshly generated
// certificate must have to pass validation.
const minNewCertificateValidity = 30 * 24 * time.Hour

// ValidateMaterial validates the isolated material before anything is
// switched: every key pair must parse and match, every leaf certificate must
// be signed by its CA, certificates must currently be valid, the new admin and
// API server certificates must keep every SAN of the current generation, the
// service account key pair must match (kind profile), and the trust chains
// must complete a real TLS handshake.
func ValidateMaterial(dir string, profile Profile, livePkiDir string, now time.Time) error {
	if profile != ProfileCore && profile != ProfileKind {
		return fmt.Errorf("unknown material profile %q", profile)
	}

	pairs := map[string]*certKeyPair{}
	for _, rel := range allFiles(profile) {
		if !strings.HasSuffix(rel, ".crt") {
			continue
		}
		base := strings.TrimSuffix(rel, ".crt")
		pair, err := readPairAt(dir, base)
		if err != nil {
			return fmt.Errorf("failed to read new %s: %w", base, err)
		}
		pairs[base] = pair
	}

	ca, ok := pairs["ca"]
	if !ok {
		return errors.New("new generation is missing the root CA")
	}
	if err := validateCertificateAuthority(ca.cert, now); err != nil {
		return fmt.Errorf("invalid root CA: %w", err)
	}

	rootChildren := []string{"admin"}
	if profile == ProfileKind {
		rootChildren = append(rootChildren, "apiserver", "apiserver-kubelet-client")
	}
	for _, name := range rootChildren {
		if err := validateLeaf(pairs[name], ca, now); err != nil {
			return fmt.Errorf("invalid %s certificate: %w", name, err)
		}
	}

	// The admin credential is the serving and client certificate of the
	// binary/compose profiles, so it must cover the current SANs.
	if err := validateSANsSuperset(livePkiDir, "admin.crt", pairs["admin"].cert); err != nil {
		return err
	}

	if profile == ProfileKind {
		if err := validateKindMaterial(dir, pairs, livePkiDir, now); err != nil {
			return err
		}
	}

	// End to end smoke test of the new chain, fully in isolation: the admin
	// credential serves TLS and authenticates clients against the new CA.
	if err := tlsHandshakeSmoke(ca.cert, pairs["admin"], pairs["admin"], "localhost"); err != nil {
		return fmt.Errorf("new root trust chain failed the TLS handshake check: %w", err)
	}

	return nil
}

func validateKindMaterial(dir string, pairs map[string]*certKeyPair, livePkiDir string, now time.Time) error {
	frontProxyCA, ok := pairs["front-proxy-ca"]
	if !ok {
		return errors.New("new generation is missing the front proxy CA")
	}
	if err := validateCertificateAuthority(frontProxyCA.cert, now); err != nil {
		return fmt.Errorf("invalid front proxy CA: %w", err)
	}
	if err := validateLeaf(pairs["front-proxy-client"], frontProxyCA, now); err != nil {
		return fmt.Errorf("invalid front-proxy-client certificate: %w", err)
	}

	etcdCA, ok := pairs["etcd/ca"]
	if !ok {
		return errors.New("new generation is missing the etcd CA")
	}
	if err := validateCertificateAuthority(etcdCA.cert, now); err != nil {
		return fmt.Errorf("invalid etcd CA: %w", err)
	}
	for _, name := range []string{"etcd/server", "etcd/peer", "etcd/healthcheck-client", "apiserver-etcd-client"} {
		if err := validateLeaf(pairs[name], etcdCA, now); err != nil {
			return fmt.Errorf("invalid %s certificate: %w", name, err)
		}
	}

	if err := validateSANsSuperset(livePkiDir, filepath.Join("etcd", "server.crt"), pairs["etcd/server"].cert); err != nil {
		return err
	}
	if err := validateSANsSuperset(livePkiDir, "apiserver.crt", pairs["apiserver"].cert); err != nil {
		return err
	}

	if err := validateServiceAccountKeyPair(dir); err != nil {
		return err
	}

	if len(pairs["etcd/server"].cert.DNSNames) > 0 {
		if err := tlsHandshakeSmoke(etcdCA.cert, pairs["etcd/server"], pairs["etcd/healthcheck-client"], pairs["etcd/server"].cert.DNSNames[0]); err != nil {
			return fmt.Errorf("new etcd trust chain failed the TLS handshake check: %w", err)
		}
	}
	return nil
}

func validateCertificateAuthority(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return errors.New("missing certificate")
	}
	if !cert.IsCA {
		return errors.New("certificate is not a CA")
	}
	return validateValidityWindow(cert, now)
}

func validateLeaf(leaf, parent *certKeyPair, now time.Time) error {
	if leaf == nil {
		return errors.New("missing certificate")
	}
	if parent == nil {
		return errors.New("missing issuer CA")
	}
	if err := validateValidityWindow(leaf.cert, now); err != nil {
		return err
	}
	if err := leaf.cert.CheckSignatureFrom(parent.cert); err != nil {
		return fmt.Errorf("certificate is not signed by %s: %w", parent.base, err)
	}
	pubKey, err := x509.MarshalPKIXPublicKey(leaf.key.Public())
	if err != nil {
		return err
	}
	certPubKey, err := x509.MarshalPKIXPublicKey(leaf.cert.PublicKey)
	if err != nil {
		return err
	}
	if !slices.Equal(pubKey, certPubKey) {
		return errors.New("certificate public key does not match the private key")
	}
	return nil
}

func validateValidityWindow(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not valid before %s", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired at %s", cert.NotAfter)
	}
	if cert.NotAfter.Sub(now) < minNewCertificateValidity {
		return fmt.Errorf("certificate expires too soon (%s)", cert.NotAfter)
	}
	return nil
}

func validateSANsSuperset(livePkiDir, rel string, newCert *x509.Certificate) error {
	oldCert, err := readCertificateFile(filepath.Join(livePkiDir, rel))
	if err != nil {
		if os.IsNotExist(err) {
			// The current generation does not have this leaf, nothing to stay
			// compatible with.
			return nil
		}
		return fmt.Errorf("failed to read current %s: %w", rel, err)
	}
	oldDNS := sets.NewSets(oldCert.DNSNames...)
	newDNS := sets.NewSets(newCert.DNSNames...)
	for name := range oldDNS {
		if !newDNS.Has(name) {
			return fmt.Errorf("new %s would drop SAN %q", rel, name)
		}
	}
	oldIPs := map[string]struct{}{}
	for _, ip := range oldCert.IPAddresses {
		oldIPs[ip.String()] = struct{}{}
	}
	newIPs := sets.NewSets[string]()
	for _, ip := range newCert.IPAddresses {
		newIPs.Insert(ip.String())
	}
	for ip := range oldIPs {
		if !newIPs.Has(ip) {
			return fmt.Errorf("new %s would drop SAN IP %q", rel, ip)
		}
	}
	return nil
}

func validateServiceAccountKeyPair(dir string) error {
	key, err := readKeyFile(filepath.Join(dir, "sa.key"))
	if err != nil {
		return fmt.Errorf("invalid service account key: %w", err)
	}
	pubBlock := func() (*pem.Block, error) {
		data, err := os.ReadFile(filepath.Join(dir, "sa.pub"))
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("failed to decode service account public key PEM")
		}
		return block, nil
	}
	block, err := pubBlock()
	if err != nil {
		return err
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid service account public key: %w", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	if !slices.Equal(keyDER, pubDER) {
		return errors.New("service account public key does not match sa.key")
	}
	return nil
}

// tlsHandshakeSmoke starts a local TLS server that presents serverPair and
// requires client certificates signed by ca, then connects to it as a client
// presenting clientPair. This proves the whole new chain works without
// touching the running cluster.
func tlsHandshakeSmoke(ca *x509.Certificate, server, client *certKeyPair, serverName string) error {
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
	}()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() {
			_ = conn.Close()
		}()
		serverConn := tls.Server(conn, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caPool,
			Certificates: []tls.Certificate{certificateOf(server)},
		})
		err = serverConn.Handshake()
		serverErr <- err
	}()

	clientConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            caPool,
		ServerName:         serverName,
		InsecureSkipVerify: false,
		Certificates:       []tls.Certificate{certificateOf(client)},
	})
	if err != nil {
		return fmt.Errorf("client handshake failed: %w", err)
	}
	defer func() {
		_ = clientConn.Close()
	}()
	if err := <-serverErr; err != nil {
		return fmt.Errorf("server handshake failed: %w", err)
	}
	return nil
}

func certificateOf(pair *certKeyPair) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{pair.cert.Raw},
		PrivateKey:  pair.key,
		Leaf:        pair.cert,
	}
}
