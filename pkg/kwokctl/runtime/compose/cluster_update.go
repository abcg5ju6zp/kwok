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

	"sigs.k8s.io/kwok/pkg/apis/internalversion"
	"sigs.k8s.io/kwok/pkg/kwokctl/runtime"
)

// setupComponents renders and ensures every enabled component (including its
// image and support files) without creating or starting its container. It is
// shared by cluster installation and component updates.
func (c *Cluster) setupComponents(ctx context.Context, e *env) error {
	if err := c.addEtcd(ctx, e); err != nil {
		return err
	}
	if err := c.addKubeApiserver(ctx, e); err != nil {
		return err
	}
	if err := c.addKubectlProxy(ctx, e); err != nil {
		return err
	}
	if err := c.addKubeControllerManager(ctx, e); err != nil {
		return err
	}
	if err := c.addKubeScheduler(ctx, e); err != nil {
		return err
	}
	if err := c.addKwokController(ctx, e); err != nil {
		return err
	}
	if err := c.addMetricsServer(ctx, e); err != nil {
		return err
	}
	if err := c.addPrometheus(ctx, e); err != nil {
		return err
	}
	if err := c.addJaeger(ctx, e); err != nil {
		return err
	}
	if err := c.addSchedulerPlugins(ctx, e); err != nil {
		return err
	}
	if err := c.addKueue(ctx, e); err != nil {
		return err
	}
	if err := c.addKueueviz(ctx, e); err != nil {
		return err
	}
	if err := c.addJobSet(ctx, e); err != nil {
		return err
	}
	if err := c.addLWS(ctx, e); err != nil {
		return err
	}
	if err := c.addDescheduler(ctx, e); err != nil {
		return err
	}
	if err := c.addNodeReadinessController(ctx, e); err != nil {
		return err
	}
	if err := c.setupPrometheusConfig(ctx, e); err != nil {
		return err
	}

	for i := range e.kwokctlConfig.Components {
		runtime.ApplyComponentPatches(ctx, &e.kwokctlConfig.Components[i], e.kwokctlConfig.ComponentsPatches)
	}

	return nil
}

// RenderComponents implements runtime.ComponentUpdater. It rebuilds
// conf.Components from conf.Options, pulling/loading the required images into
// the cache and regenerating support files. Running containers are untouched.
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
		&env.kwokctlConfig.Options.KubeApiserverPort,
	); err != nil {
		return nil, err
	}

	if err := c.preInstall(ctx, env); err != nil {
		return nil, err
	}

	if err := c.setupComponents(ctx, env); err != nil {
		return nil, err
	}

	// The container network must exist before new containers can be created;
	// creation is a no-op when the cluster already has it.
	if err := c.createNetwork(ctx); err != nil {
		return nil, err
	}

	return env.kwokctlConfig, nil
}

// ApplyComponent implements runtime.ComponentUpdater. It recreates the
// container from the active specification (no-op when an identical container
// already exists) and starts it when the cluster is up. Readiness is waited for
// by the update transaction.
func (c *Cluster) ApplyComponent(ctx context.Context, name string, up bool, _ time.Duration) error {
	// Converge any leftover incarnation left over from a stopped/replaced
	// component or an interrupted transaction.
	if up {
		if err := c.StopComponent(ctx, name); err != nil {
			return err
		}
	}
	if err := c.deleteComponent(ctx, name); err != nil {
		return err
	}
	if err := c.createComponent(ctx, name); err != nil {
		return err
	}
	if up {
		return c.StartComponent(ctx, name)
	}
	return nil
}

// RemoveComponent implements runtime.ComponentUpdater. The container is removed
// (and stopped first when still running).
func (c *Cluster) RemoveComponent(ctx context.Context, name string, up bool) error {
	if up {
		if err := c.StopComponent(ctx, name); err != nil {
			return err
		}
	}
	return c.deleteComponent(ctx, name)
}
