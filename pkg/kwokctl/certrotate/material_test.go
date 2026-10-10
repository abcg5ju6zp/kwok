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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"sigs.k8s.io/kwok/pkg/kwokctl/pki"
)

func mustGenerateLivePki(t *testing.T, dir string, sans ...string) {
	t.Helper()
	if err := pki.GeneratePki(dir, sans...); err != nil {
		t.Fatalf("GeneratePki failed: %v", err)
	}
}

func mustReadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("failed to decode PEM %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestGenerateAndValidateCoreMaterial(t *testing.T) {
	t.Parallel()
	live := t.TempDir()
	mustGenerateLivePki(t, live, "extra-dns.example", "10.9.8.7")

	dst := filepath.Join(t.TempDir(), "new")
	ctx := context.Background()
	if err := GenerateMaterial(ctx, dst, ProfileCore, "kwok-test", []string{"10.1.2.3"}, live); err != nil {
		t.Fatalf("GenerateMaterial failed: %v", err)
	}

	for _, name := range []string{"ca.crt", "ca.key", "admin.crt", "admin.key"} {
		if _, err := os.Stat(filepath.Join(dst, name)); err != nil {
			t.Fatalf("expected %s to be generated: %v", name, err)
		}
	}

	if err := ValidateMaterial(dst, ProfileCore, live, time.Now()); err != nil {
		t.Fatalf("ValidateMaterial failed: %v", err)
	}

	// The new generation must keep the SANs of the current one and add the new ones.
	adminCert := mustReadCert(t, filepath.Join(dst, "admin.crt"))
	dns := adminCert.DNSNames
	if !slices.Contains(dns, "extra-dns.example") {
		t.Errorf("new admin cert dropped existing DNS SAN, got %v", dns)
	}
	if !slices.Contains(dns, "localhost") {
		t.Errorf("new admin cert dropped default SAN, got %v", dns)
	}
	ips := map[string]struct{}{}
	for _, ip := range adminCert.IPAddresses {
		ips[ip.String()] = struct{}{}
	}
	if _, ok := ips["10.9.8.7"]; !ok {
		t.Errorf("new admin cert dropped existing IP SAN, got %v", ips)
	}
	if _, ok := ips["10.1.2.3"]; !ok {
		t.Errorf("new admin cert is missing extra IP SAN, got %v", ips)
	}

	// The new CA must actually differ from the current one.
	liveCA := mustReadCert(t, filepath.Join(live, "ca.crt"))
	if adminCert.CheckSignatureFrom(liveCA) == nil {
		t.Error("new admin certificate is still signed by the old CA")
	}
}

func TestGenerateAndValidateKindMaterial(t *testing.T) {
	t.Parallel()
	live := t.TempDir()
	// Simulate the kubeadm material that exists in a kind cluster.
	mustGenerateKindLivePki(t, live)

	dst := filepath.Join(t.TempDir(), "new")
	if err := GenerateMaterial(context.Background(), dst, ProfileKind, "kwok-test", nil, live); err != nil {
		t.Fatalf("GenerateMaterial failed: %v", err)
	}

	for _, name := range append(append([]string{}, kindEtcdFiles...), kindMainFiles...) {
		if _, err := os.Stat(filepath.Join(dst, name)); err != nil {
			t.Fatalf("expected %s to be generated: %v", name, err)
		}
	}

	if err := ValidateMaterial(dst, ProfileKind, live, time.Now()); err != nil {
		t.Fatalf("ValidateMaterial failed: %v", err)
	}
}

func TestValidateRejectsMismatchedKey(t *testing.T) {
	t.Parallel()
	live := t.TempDir()
	mustGenerateLivePki(t, live)
	dst := filepath.Join(t.TempDir(), "new")
	if err := GenerateMaterial(context.Background(), dst, ProfileCore, "kwok-test", nil, live); err != nil {
		t.Fatalf("GenerateMaterial failed: %v", err)
	}

	// Pair admin.crt with ca.key: the public keys no longer match.
	caKey, err := os.ReadFile(filepath.Join(dst, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "admin.key"), caKey, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ValidateMaterial(dst, ProfileCore, live, time.Now()); err == nil {
		t.Fatal("expected validation to fail for a mismatched key pair")
	}
}

func TestValidateRejectsExpiredCA(t *testing.T) {
	t.Parallel()
	live := t.TempDir()
	mustGenerateLivePki(t, live)
	dst := filepath.Join(t.TempDir(), "new")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	caCert, caKey, err := pki.GenerateCA(pki.DefaultCN, now.Add(-10*24*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteCertAndKey(dst, "ca", caCert, caKey); err != nil {
		t.Fatal(err)
	}
	cert, key, err := pki.GenerateSignCert(pki.DefaultUser, caCert, caKey, now.Add(-10*24*time.Hour), now.Add(-time.Hour), pki.DefaultGroups, pki.DefaultAltNames)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteCertAndKey(dst, "admin", cert, key); err != nil {
		t.Fatal(err)
	}

	if err := ValidateMaterial(dst, ProfileCore, live, now); err == nil {
		t.Fatal("expected validation to fail with an expired CA")
	}
}

func TestValidateRejectsDroppedSANs(t *testing.T) {
	t.Parallel()
	// Current generation serves a SAN that the new generation is not built with.
	live := t.TempDir()
	mustGenerateLivePki(t, live, "must-keep.example")

	dst := filepath.Join(t.TempDir(), "new")
	// Pass no extra SANs and point at an empty predecessor so the SAN cannot be
	// inherited. The default SANs alone are generated.
	empty := t.TempDir()
	if err := GenerateMaterial(context.Background(), dst, ProfileCore, "kwok-test", nil, empty); err != nil {
		t.Fatalf("GenerateMaterial failed: %v", err)
	}
	// Validation must compare against the real live directory that holds the
	// extra SAN.
	if err := ValidateMaterial(dst, ProfileCore, live, time.Now()); err == nil {
		t.Fatal("expected validation to fail when a SAN would be dropped")
	}
}

// mustGenerateKindLivePki produces the full set of files that kubeadm creates
// in a kind cluster, using independent CAs like kubeadm does.
func mustGenerateKindLivePki(t *testing.T, dir string) {
	t.Helper()
	mustGenerateLivePki(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, "etcd"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(pki.CertificateValidity)

	caCert, caKey, err := pki.ReadCertAndKey(dir, "ca")
	if err != nil {
		t.Fatal(err)
	}

	writePair := func(subdir, name, cn string, groups, sans []string, parent *x509.Certificate, parentKey crypto.Signer) {
		t.Helper()
		target := dir
		if subdir != "" {
			target = filepath.Join(dir, subdir)
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		cert, key, err := pki.GenerateSignCert(cn, parent, parentKey, notBefore, notAfter, groups, sans)
		if err != nil {
			t.Fatal(err)
		}
		if err := pki.WriteCertAndKey(target, name, cert, key); err != nil {
			t.Fatal(err)
		}
	}

	writePair("", "apiserver", "kube-apiserver", nil, append([]string{"localhost", "kwok-test-control-plane"}, "127.0.0.1"), caCert, caKey)
	writePair("", "apiserver-kubelet-client", "kube-apiserver-kubelet-client", []string{"system:masters"}, nil, caCert, caKey)

	fpCA, fpKey, err := pki.GenerateCA("front-proxy-ca", notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteCertAndKey(dir, "front-proxy-ca", fpCA, fpKey); err != nil {
		t.Fatal(err)
	}
	writePair("", "front-proxy-client", "front-proxy-client", nil, nil, fpCA, fpKey)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := pki.EncodePrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sa.key"), keyPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sa.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}

	etcdCA, etcdKey, err := pki.GenerateCA("etcd-ca", notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.WriteCertAndKey(filepath.Join(dir, "etcd"), "ca", etcdCA, etcdKey); err != nil {
		t.Fatal(err)
	}
	writePair("etcd", "server", "kube-etcd-server", nil, []string{"localhost", "127.0.0.1", "kwok-test-control-plane"}, etcdCA, etcdKey)
	writePair("etcd", "peer", "kube-etcd-peer", nil, []string{"kwok-test-control-plane", "127.0.0.1"}, etcdCA, etcdKey)
	writePair("etcd", "healthcheck-client", "kube-apiserver-healthcheck", []string{"system:masters"}, nil, etcdCA, etcdKey)
	writePair("", "apiserver-etcd-client", "kube-apiserver-etcd-client", []string{"system:masters"}, nil, etcdCA, etcdKey)
}
