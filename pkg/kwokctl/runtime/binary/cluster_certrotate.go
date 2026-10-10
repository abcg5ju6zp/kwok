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

package binary

import (
	"context"
	"time"

	"sigs.k8s.io/kwok/pkg/kwokctl/certrotate"
	"sigs.k8s.io/kwok/pkg/kwokctl/dryrun"
	"sigs.k8s.io/kwok/pkg/kwokctl/runtime"
	"sigs.k8s.io/kwok/pkg/log"
	utilsnet "sigs.k8s.io/kwok/pkg/utils/net"
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

func (h *rotationHooks) SwitchComponent(ctx context.Context, name string, _ certrotate.Generation) error {
	return h.RestartComponent(ctx, name)
}

func (h *rotationHooks) RestartComponent(ctx context.Context, name string) error {
	if err := h.cluster.StopComponent(ctx, name); err != nil {
		return err
	}
	return h.cluster.StartComponent(ctx, name)
}

func (h *rotationHooks) RestoreComponent(context.Context, string, certrotate.Generation) error {
	return nil
}

func (h *rotationHooks) VerifyAccess(ctx context.Context) error {
	return h.cluster.waitServed(ctx, 2*time.Minute)
}

func (h *rotationHooks) PublishClients(ctx context.Context, gen certrotate.Generation) error {
	env, err := h.cluster.env(ctx)
	if err != nil {
		return err
	}
	if err := certrotate.BackupFiles(gen.ClientsBackupDir(), []string{env.inClusterKubeconfigPath}); err != nil {
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
