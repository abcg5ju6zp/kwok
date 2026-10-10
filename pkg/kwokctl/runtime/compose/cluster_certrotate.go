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

package compose

import (
	"context"
	"time"

	"sigs.k8s.io/kwok/pkg/kwokctl/certrotate"
	"sigs.k8s.io/kwok/pkg/kwokctl/dryrun"
	"sigs.k8s.io/kwok/pkg/kwokctl/runtime"
	"sigs.k8s.io/kwok/pkg/log"
	utilsnet "sigs.k8s.io/kwok/pkg/utils/net"
	"sigs.k8s.io/kwok/pkg/utils/wait"
)

// RotateCertificates rotates the CA and all certificates of the running
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
	return certrotate.ProfileCore
}

func (h *rotationHooks) ExtraSANs(ctx context.Context) ([]string, error) {
	conf, err := h.cluster.Config(ctx)
	if err != nil {
		return nil, err
	}
	sans := []string{
		h.cluster.Name() + "-kube-apiserver",
		h.cluster.Name() + "-kwok-controller",
	}
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

func (h *rotationHooks) SwitchComponent(ctx context.Context, name string, _ certrotate.Generation) error {
	return h.restartComponent(ctx, name)
}

func (h *rotationHooks) RestartComponent(ctx context.Context, name string) error {
	return h.restartComponent(ctx, name)
}

// restartComponent recreates the container of the component. A plain stop and
// start would keep the container and therefore the old bind mount inode, so
// the container has to be removed and recreated to pick up the replaced
// certificate files.
func (h *rotationHooks) restartComponent(ctx context.Context, name string) error {
	c := h.cluster
	logger := log.FromContext(ctx).With("component", name)

	if err := c.StopComponent(ctx, name); err != nil {
		return err
	}
	if err := c.deleteComponent(ctx, name); err != nil {
		return err
	}
	if err := c.createComponent(ctx, name); err != nil {
		return err
	}
	if err := c.StartComponent(ctx, name); err != nil {
		return err
	}

	// Wait until the container is actually running again.
	err := wait.Poll(ctx, func(ctx context.Context) (bool, error) {
		running, exist := c.inspectComponent(ctx, name)
		if !exist {
			return false, nil
		}
		return running, nil
	},
		wait.WithTimeout(2*time.Minute),
		wait.WithInterval(time.Second),
		wait.WithImmediate(),
	)
	if err != nil {
		logger.Error("Component is not running after the certificate switch",
			"err", err,
		)
		return err
	}
	return nil
}

func (h *rotationHooks) RestoreComponent(context.Context, string, certrotate.Generation) error {
	return nil
}

func (h *rotationHooks) VerifyAccess(ctx context.Context) error {
	clientset, err := h.cluster.GetClientset(ctx)
	if err != nil {
		return err
	}
	discovery, err := clientset.ToDiscoveryClient()
	if err != nil {
		return err
	}
	_, err = discovery.ServerVersion()
	return err
}

func (h *rotationHooks) PublishClients(ctx context.Context, gen certrotate.Generation) error {
	env, err := h.cluster.env(ctx)
	if err != nil {
		return err
	}
	if err := certrotate.BackupFiles(gen.ClientsBackupDir(), []string{env.inClusterOnHostKubeconfigPath}); err != nil {
		return err
	}
	return h.cluster.writeInClusterKubeconfig(env)
}

func (h *rotationHooks) RestoreClients(_ context.Context, gen certrotate.Generation) error {
	return certrotate.RestoreFiles(gen.ClientsBackupDir())
}

func (h *rotationHooks) PublishKubeconfig(ctx context.Context, gen certrotate.Generation) error {
	env, err := h.cluster.env(ctx)
	if err != nil {
		return err
	}
	if err := certrotate.BackupFiles(gen.KubeconfigBackupDir(), []string{env.kubeconfigPath}); err != nil {
		return err
	}
	return h.cluster.writeHostKubeconfig(env)
}

func (h *rotationHooks) RestoreKubeconfig(_ context.Context, gen certrotate.Generation) error {
	return certrotate.RestoreFiles(gen.KubeconfigBackupDir())
}
