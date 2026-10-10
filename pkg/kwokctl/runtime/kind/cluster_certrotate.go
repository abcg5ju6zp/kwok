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

package kind

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/kwok/pkg/apis/internalversion"
	"sigs.k8s.io/kwok/pkg/consts"
	"sigs.k8s.io/kwok/pkg/kwokctl/certrotate"
	"sigs.k8s.io/kwok/pkg/kwokctl/dryrun"
	"sigs.k8s.io/kwok/pkg/kwokctl/pki"
	"sigs.k8s.io/kwok/pkg/kwokctl/runtime"
	"sigs.k8s.io/kwok/pkg/log"
	utilsexec "sigs.k8s.io/kwok/pkg/utils/exec"
	"sigs.k8s.io/kwok/pkg/utils/file"
	"sigs.k8s.io/kwok/pkg/utils/kubeconfig"
	utilsnet "sigs.k8s.io/kwok/pkg/utils/net"
	"sigs.k8s.io/kwok/pkg/utils/wait"
)

// RotateCertificates rotates the CA and all certificates of the running kind
// cluster.
func (c *Cluster) RotateCertificates(ctx context.Context) error {
	if c.IsDryRun() {
		dryrun.PrintMessagef("# Rotate certificates of cluster %s", c.Name())
		return nil
	}

	conf, err := c.Config(ctx)
	if err != nil {
		return err
	}
	if !conf.Options.SecurePort {
		log.FromContext(ctx).Info("Cluster does not serve a secure port, skipping certificate rotation")
		return nil
	}

	return certrotate.Rotate(ctx, &rotationHooks{cluster: c})
}

type rotationHooks struct {
	cluster *Cluster
}

func (h *rotationHooks) ClusterName() string {
	return h.cluster.Name()
}

func (h *rotationHooks) PkiDir() string {
	return h.cluster.GetWorkdirPath(runtime.PkiName)
}

func (h *rotationHooks) Profile() certrotate.Profile {
	return certrotate.ProfileKind
}

func (h *rotationHooks) ExtraSANs(ctx context.Context) ([]string, error) {
	conf, err := h.cluster.Config(ctx)
	if err != nil {
		return nil, err
	}
	sans := []string{}
	ips, err := utilsnet.GetAllIPs()
	if err != nil {
		log.FromContext(ctx).Warn("failed to get all ips",
			"err", err,
		)
	} else {
		sans = append(sans, ips...)
	}
	sans = append(sans, conf.Options.KubeApiserverCertSANs...)
	return sans, nil
}

func (h *rotationHooks) EnabledComponents(ctx context.Context) ([]string, error) {
	components, err := h.cluster.ListComponents(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(components))
	for _, component := range components {
		names = append(names, component.Name)
	}
	return names, nil
}

// nodeComponentKubeconfig maps a static component to the kubeconfig file that
// kubeadm generated for it inside the node.
var nodeComponentKubeconfig = map[string]string{
	consts.ComponentKubeControllerManager: "controller-manager.conf",
	consts.ComponentKubeScheduler:         "scheduler.conf",
}

func (h *rotationHooks) SwitchComponent(ctx context.Context, name string, gen certrotate.Generation) error {
	if confName, ok := nodeComponentKubeconfig[name]; ok {
		if err := h.publishNodeKubeconfig(ctx, confName, gen, true); err != nil {
			return err
		}
	}
	return h.restartComponent(ctx, name)
}

func (h *rotationHooks) RestartComponent(ctx context.Context, name string) error {
	return h.restartComponent(ctx, name)
}

func (h *rotationHooks) RestoreComponent(ctx context.Context, name string, gen certrotate.Generation) error {
	confName, ok := nodeComponentKubeconfig[name]
	if !ok {
		return nil
	}
	backup := filepath.Join(gen.NodeBackupDir(), confName)
	if !file.Exists(backup) {
		return nil
	}
	return h.copyIntoNode(ctx, backup, "/etc/kubernetes/"+confName)
}

// restartComponent moves the static pod manifest out of the manifests
// directory and back, which makes the kubelet restart the component, and then
// waits for the container to run. It deliberately does not use the host
// kubeconfig because that is switched in a later stage.
func (h *rotationHooks) restartComponent(ctx context.Context, name string) error {
	c := h.cluster
	node := c.getClusterName()
	logger := log.FromContext(ctx).With("component", name)

	if err := c.Exec(ctx, c.runtime, "exec", node, "mv", "/etc/kubernetes/manifests/"+name+".yaml", "/etc/kubernetes/"+name+".yaml.bak"); err != nil {
		return fmt.Errorf("failed to stop %s: %w", name, err)
	}
	if err := wait.Poll(ctx, func(ctx context.Context) (bool, error) {
		return !h.componentContainerRunning(ctx, name), nil
	},
		wait.WithTimeout(2*time.Minute),
		wait.WithInterval(time.Second),
		wait.WithImmediate(),
	); err != nil {
		return fmt.Errorf("failed to wait for %s to stop: %w", name, err)
	}

	if err := c.Exec(ctx, c.runtime, "exec", node, "mv", "/etc/kubernetes/"+name+".yaml.bak", "/etc/kubernetes/manifests/"+name+".yaml"); err != nil {
		return fmt.Errorf("failed to start %s: %w", name, err)
	}
	if err := wait.Poll(ctx, func(ctx context.Context) (bool, error) {
		return h.componentContainerRunning(ctx, name), nil
	},
		wait.WithTimeout(2*time.Minute),
		wait.WithInterval(time.Second),
		wait.WithImmediate(),
	); err != nil {
		logger.Error("Component is not running after the certificate switch",
			"err", err,
		)
		return fmt.Errorf("failed to wait for %s to run: %w", name, err)
	}
	return nil
}

// componentContainerRunning checks crictl inside the node, so it does not
// depend on the host kubeconfig while the trust chain is being switched.
func (h *rotationHooks) componentContainerRunning(ctx context.Context, name string) bool {
	c := h.cluster
	buf := bytes.NewBuffer(nil)
	err := c.Exec(utilsexec.WithWriteTo(ctx, buf), c.runtime, "exec", c.getClusterName(),
		"crictl", "ps", "--state", "Running", "--name", name)
	if err != nil {
		return false
	}
	return strings.Contains(buf.String(), name)
}

func (h *rotationHooks) copyFromNode(ctx context.Context, nodePath, hostPath string) error {
	c := h.cluster
	node := c.getClusterName()
	return c.Exec(ctx, c.runtime, "cp", node+":"+nodePath, hostPath)
}

func (h *rotationHooks) copyIntoNode(ctx context.Context, hostPath, nodePath string) error {
	c := h.cluster
	node := c.getClusterName()
	return c.Exec(ctx, c.runtime, "cp", hostPath, node+":"+nodePath)
}

// publishNodeKubeconfig replaces the embedded credentials of a kubeconfig
// running inside the node. The current file is backed up first so that a
// component switch failure can be rolled back.
func (h *rotationHooks) publishNodeKubeconfig(ctx context.Context, confName string, gen certrotate.Generation, componentCert bool) error {
	nodePath := "/etc/kubernetes/" + confName

	backupDir := gen.NodeBackupDir()
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return err
	}
	backupPath := filepath.Join(backupDir, confName)
	if err := h.copyFromNode(ctx, nodePath, backupPath); err != nil {
		// A missing kubeconfig means the component does not consume one.
		logger := log.FromContext(ctx)
		logger.Debug("Component kubeconfig not found in node, skipping credential publish",
			"path", nodePath,
			"err", err,
		)
		_ = os.Remove(backupPath)
		return nil
	}

	newConf, err := h.buildNodeKubeconfig(backupPath, confName, gen, componentCert)
	if err != nil {
		return err
	}
	staging := filepath.Join(gen.NewDir, "node", confName)
	if err := os.MkdirAll(filepath.Dir(staging), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(staging, newConf, 0o600); err != nil {
		return err
	}
	if err := h.copyIntoNode(ctx, staging, nodePath); err != nil {
		return err
	}
	return nil
}

// buildNodeKubeconfig rewrites a kubeadm style kubeconfig (controller-manager,
// scheduler, admin) in place, preserving its server address but embedding
// credentials of the target generation.
func (h *rotationHooks) buildNodeKubeconfig(currentPath, confName string, gen certrotate.Generation, componentCert bool) ([]byte, error) {
	raw, err := os.ReadFile(currentPath)
	if err != nil {
		return nil, err
	}
	cfg, err := kubeconfig.DecodeKubeconfig(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode node kubeconfig %s: %w", confName, err)
	}

	caPEM, err := os.ReadFile(filepath.Join(gen.NewDir, "ca.crt"))
	if err != nil {
		return nil, err
	}

	var (
		certPEM []byte
		keyPEM  []byte
	)
	if componentCert {
		// Components get a fresh dedicated leaf signed by the new CA.
		leaf, err := h.generateComponentCredential(confName, gen)
		if err != nil {
			return nil, err
		}
		certPEM, keyPEM = leaf.certPEM, leaf.keyPEM
	} else {
		certPEM, err = os.ReadFile(filepath.Join(gen.NewDir, "admin.crt"))
		if err != nil {
			return nil, err
		}
		keyPEM, err = os.ReadFile(filepath.Join(gen.NewDir, "admin.key"))
		if err != nil {
			return nil, err
		}
	}

	for cluster := range cfg.Clusters {
		cfg.Clusters[cluster].CertificateAuthorityData = caPEM
		cfg.Clusters[cluster].CertificateAuthority = ""
	}
	for user := range cfg.AuthInfos {
		cfg.AuthInfos[user].ClientCertificateData = certPEM
		cfg.AuthInfos[user].ClientCertificate = ""
		cfg.AuthInfos[user].ClientKeyData = keyPEM
		cfg.AuthInfos[user].ClientKey = ""
	}

	return kubeconfig.EncodeKubeconfig(cfg)
}

type nodeCredential struct {
	certPEM []byte
	keyPEM  []byte
}

// generateComponentCredential creates the dedicated client leaf used by a
// kubeadm component kubeconfig.
func (h *rotationHooks) generateComponentCredential(confName string, gen certrotate.Generation) (nodeCredential, error) {
	caCert, err := readCertificate(filepath.Join(gen.NewDir, "ca.crt"))
	if err != nil {
		return nodeCredential{}, err
	}
	caKey, err := readSigner(filepath.Join(gen.NewDir, "ca.key"))
	if err != nil {
		return nodeCredential{}, err
	}

	now := time.Now()
	notBefore := now.Add(-24 * time.Hour).UTC()
	notAfter := now.Add(pki.CertificateValidity).UTC()

	var cn, org string
	switch confName {
	case "controller-manager.conf":
		cn = "system:kube-controller-manager"
		org = "system:kube-controller-manager"
	case "scheduler.conf":
		cn = "system:kube-scheduler"
		org = "system:kube-scheduler"
	default:
		cn = "system:" + strings.TrimSuffix(confName, ".conf")
	}
	cert, key, err := pki.GenerateSignCert(cn, caCert, caKey, notBefore, notAfter, []string{org}, nil)
	if err != nil {
		return nodeCredential{}, err
	}
	keyPEM, err := pki.EncodePrivateKeyToPEM(key)
	if err != nil {
		return nodeCredential{}, err
	}
	return nodeCredential{certPEM: pki.EncodeCertToPEM(cert), keyPEM: keyPEM}, nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func readSigner(path string) (crypto.Signer, error) {
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
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case pki.ECPrivateKeyBlockType:
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %q in %s", block.Type, path)
	}
}

// VerifyAccess checks /healthz through the new CA inside the node. It requires
// neither the host kubeconfig nor client credentials, so it works as soon as
// the API server serves the new generation.
func (h *rotationHooks) VerifyAccess(ctx context.Context) error {
	c := h.cluster
	return c.Exec(ctx, c.runtime, "exec", c.getClusterName(),
		"curl", "-fsS", "--cacert", "/etc/kubernetes/pki/ca.crt",
		"https://127.0.0.1:6443/healthz")
}

func (h *rotationHooks) PublishClients(ctx context.Context, gen certrotate.Generation) error {
	// admin.conf is the client credential used inside the node.
	if err := h.publishNodeKubeconfig(ctx, "admin.conf", gen, false); err != nil {
		return err
	}
	// kubeadm writes certificates as root; keep them readable like the initial
	// bring up does.
	c := h.cluster
	if err := c.Exec(ctx, c.runtime, "exec", c.getClusterName(), "chmod", "-R", "+r", "/etc/kubernetes/pki"); err != nil {
		log.FromContext(ctx).Warn("Failed to chmod pki",
			"err", err,
		)
	}
	return nil
}

func (h *rotationHooks) RestoreClients(ctx context.Context, gen certrotate.Generation) error {
	backup := filepath.Join(gen.NodeBackupDir(), "admin.conf")
	if !file.Exists(backup) {
		return nil
	}
	return h.copyIntoNode(ctx, backup, "/etc/kubernetes/admin.conf")
}

// writeHostKubeconfig refreshes the host kubeconfig of the cluster from the
// kubeconfig managed inside the node. It is shared by cluster creation and
// certificate rotation.
func (c *Cluster) writeHostKubeconfig(ctx context.Context, conf *internalversion.KwokctlConfigurationOptions) error {
	// kind itself fills the default kubeconfig; only the server address has to
	// be adjusted afterwards.
	if err := c.fillKubeconfigContextServer(conf.BindAddress); err != nil {
		return err
	}

	kubeconfigPath := c.GetWorkdirPath(runtime.InHostKubeconfigName)
	kubeconfigBuf := bytes.NewBuffer(nil)
	if err := c.Kubectl(utilsexec.WithWriteTo(ctx, kubeconfigBuf), "config", "view", "--minify=true", "--raw=true"); err != nil {
		return err
	}
	return c.WriteFile(kubeconfigPath, kubeconfigBuf.Bytes())
}

func (h *rotationHooks) PublishKubeconfig(ctx context.Context, gen certrotate.Generation) error {
	c := h.cluster

	hostKubeconfig := c.GetWorkdirPath(runtime.InHostKubeconfigName)
	if err := certrotate.BackupFiles(gen.KubeconfigBackupDir(), []string{hostKubeconfig}); err != nil {
		return err
	}

	// Re-export the kubeconfig that kind manages from the node admin.conf.
	kindPath, err := c.preDownloadKind(ctx)
	if err != nil {
		return err
	}
	if err := c.Exec(utilsexec.WithAllWriteToErrOut(c.withProviderEnv(ctx)), kindPath,
		"export", "kubeconfig", "--name", c.Name()); err != nil {
		return fmt.Errorf("failed to export kubeconfig from kind: %w", err)
	}

	conf, err := c.Config(ctx)
	if err != nil {
		return err
	}
	return c.writeHostKubeconfig(ctx, &conf.Options)
}

func (h *rotationHooks) RestoreKubeconfig(_ context.Context, gen certrotate.Generation) error {
	return certrotate.RestoreFiles(gen.KubeconfigBackupDir())
}
