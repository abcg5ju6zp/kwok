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

	"sigs.k8s.io/kwok/pkg/apis/internalversion"
	"sigs.k8s.io/kwok/pkg/kwokctl/runtime"
)

// setupComponents renders and ensures every enabled component together with its
// support files (binaries, prometheus configuration, ...). It does not start
// any process and is shared by cluster installation and component updates.
func (c *Cluster) setupComponents(ctx context.Context, env *env) error {
	err := c.addEtcd(ctx, env)
	if err != nil {
		return err
	}

	err = c.addKubeApiserver(ctx, env)
	if err != nil {
		return err
	}

	err = c.addKubectlProxy(ctx, env)
	if err != nil {
		return err
	}

	err = c.addKubeControllerManager(ctx, env)
	if err != nil {
		return err
	}

	err = c.addKubeScheduler(ctx, env)
	if err != nil {
		return err
	}

	err = c.addKwokController(ctx, env)
	if err != nil {
		return err
	}

	err = c.addMetricsServer(ctx, env)
	if err != nil {
		return err
	}

	err = c.addPrometheus(ctx, env)
	if err != nil {
		return err
	}

	err = c.addJaeger(ctx, env)
	if err != nil {
		return err
	}

	err = c.setupPrometheusConfig(ctx, env)
	if err != nil {
		return err
	}

	for i := range env.kwokctlConfig.Components {
		runtime.ApplyComponentPatches(ctx, &env.kwokctlConfig.Components[i], env.kwokctlConfig.ComponentsPatches)
	}

	return nil
}

// RenderComponents implements runtime.ComponentUpdater. It rebuilds
// conf.Components from conf.Options, ensuring the required binaries and support
// files are available without touching running processes.
func (c *Cluster) RenderComponents(ctx context.Context, conf *internalversion.KwokctlConfiguration) (*internalversion.KwokctlConfiguration, error) {
	// Rebuild the component list from options even when the passed configuration
	// already carries rendered components (e.g. when rolling back).
	conf.Components = nil

	if err := c.SetConfig(ctx, conf); err != nil {
		return nil, err
	}

	env, err := c.env(ctx)
	if err != nil {
		return nil, err
	}

	// Idempotent scaffolding: pki, audit files and the etcd data directory.
	if err := c.setup(ctx, env); err != nil {
		return nil, err
	}

	if err := c.setupPorts(ctx,
		env.usedPorts,
		&env.kwokctlConfig.Options.EtcdPeerPort,
		&env.kwokctlConfig.Options.EtcdPort,
		&env.kwokctlConfig.Options.KubeApiserverPort,
		&env.kwokctlConfig.Options.KwokControllerPort,
	); err != nil {
		return nil, err
	}

	if env.kwokctlConfig.Options.JaegerPort != 0 {
		if err := c.setupPorts(ctx,
			env.usedPorts,
			&env.kwokctlConfig.Options.JaegerOtlpGrpcPort,
		); err != nil {
			return nil, err
		}
	}

	if err := c.setupComponents(ctx, env); err != nil {
		return nil, err
	}

	return env.kwokctlConfig, nil
}

// ApplyComponent implements runtime.ComponentUpdater. Binary components are
// forked processes whose specification comes from the active configuration, so
// starting the process is all that is required; support files were written by
// RenderComponents. When the cluster is stopped only the support files are put
// in place for the next cluster start. Readiness is waited for by the update
// transaction.
func (c *Cluster) ApplyComponent(ctx context.Context, name string, up bool, _ time.Duration) error {
	if !up {
		return nil
	}
	return c.StartComponent(ctx, name)
}

// RemoveComponent implements runtime.ComponentUpdater. It stops the process when
// necessary; process-free components leave no other resource behind.
func (c *Cluster) RemoveComponent(ctx context.Context, name string, _ bool) error {
	return c.StopComponent(ctx, name)
}
