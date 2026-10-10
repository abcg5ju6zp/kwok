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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/kwok/pkg/apis/internalversion"
	"sigs.k8s.io/kwok/pkg/consts"
	"sigs.k8s.io/kwok/pkg/kwokctl/runtime"
	"sigs.k8s.io/kwok/pkg/log"
	utilspath "sigs.k8s.io/kwok/pkg/utils/path"
)

// manifestStagingSuffix marks manifests rendered for an update that must not be
// picked up by the kubelet until the component is applied.
const manifestStagingSuffix = ".kwok-update"

// fileManagedComponents are static pod components whose manifests are rendered
// from host files bind-mounted into the kind node, so they can be replaced live.
var fileManagedComponents = map[string]struct{}{
	consts.ComponentKwokController:             {},
	consts.ComponentPrometheus:                 {},
	consts.ComponentJaeger:                     {},
	consts.ComponentMetricsServer:              {},
	consts.ComponentKubeApiserverInsecureProxy: {},
}

// coreComponents are owned by kubeadm; they can be enabled or disabled but their
// parameters cannot be changed without recreating the cluster.
var coreComponents = map[string]struct{}{
	consts.ComponentEtcd:                  {},
	consts.ComponentKubeApiserver:         {},
	consts.ComponentKubeControllerManager: {},
	consts.ComponentKubeScheduler:         {},
}

func (c *Cluster) componentManifestPath(name string) string {
	return utilspath.Join(c.GetWorkdirPath(runtime.ManifestsName), name+".yaml")
}

func (c *Cluster) stagedComponentManifestPath(name string) string {
	return c.componentManifestPath(name) + manifestStagingSuffix
}

// ValidateUpdate implements runtime.ComponentUpdateValidator.
func (c *Cluster) ValidateUpdate(_ context.Context, plan *runtime.UpdatePlan, _ *internalversion.KwokctlConfiguration) error {
	return validateKindUpdate(plan)
}

// RenderComponents implements runtime.ComponentUpdater. Rendered addon static
// pod manifests are staged beside the live manifests directory (with a suffix
// the kubelet ignores) instead of overwriting files of running pods.
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

	if err := c.preInstall(ctx, env); err != nil {
		return nil, err
	}

	// Idempotent scaffolding (pki directories).
	if err := c.setup(ctx, env); err != nil {
		return nil, err
	}

	if err := c.setupPorts(ctx,
		env.usedPorts,
		&env.kwokctlConfig.Options.KubeApiserverPort,
	); err != nil {
		return nil, err
	}

	if c.IsDryRun() {
		if err := c.setupComponents(ctx, env); err != nil {
			return nil, err
		}
		return env.kwokctlConfig, nil
	}

	manifestsDir := c.GetWorkdirPath(runtime.ManifestsName)

	// Snapshot the manifests that are currently live so they can be restored
	// after the target chain rendered its candidates into the same paths.
	backedUp, err := c.stageSnapshotManifests(manifestsDir)
	if err != nil {
		return nil, err
	}

	if err := c.setupComponents(ctx, env); err != nil {
		return nil, err
	}

	// Move the freshly rendered, file-managed manifests aside and put back the
	// currently effective ones. Nothing observable by the kubelet changes here.
	for _, component := range env.kwokctlConfig.Components {
		if _, ok := fileManagedComponents[component.Name]; !ok {
			continue
		}
		live := c.componentManifestPath(component.Name)
		staged := c.stagedComponentManifestPath(component.Name)
		if _, statErr := os.Stat(live); statErr == nil {
			if err := os.Rename(live, staged); err != nil {
				return nil, fmt.Errorf("failed to stage manifest for component %q: %w", component.Name, err)
			}
		}
	}
	if err := c.stageRestoreManifests(manifestsDir, backedUp); err != nil {
		return nil, err
	}

	return env.kwokctlConfig, nil
}

// stageSnapshotManifests copies the current *.yaml/*.bak manifests into a
// temporary backup directory and returns the backed up base file names.
func (c *Cluster) stageSnapshotManifests(manifestsDir string) ([]string, error) {
	entries, err := os.ReadDir(manifestsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	backupDir := filepath.Join(c.Workdir(), "update-manifests-backup")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".bak" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(manifestsDir, name))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(backupDir, name), data, 0o644); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

// stageRestoreManifests copies the snapshotted manifests back over the rendered
// candidates and removes the temporary backup directory.
func (c *Cluster) stageRestoreManifests(manifestsDir string, names []string) error {
	backupDir := filepath.Join(c.Workdir(), "update-manifests-backup")
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(backupDir, name))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(manifestsDir, name), data, 0o644); err != nil {
			return err
		}
	}
	return os.RemoveAll(backupDir)
}

// ApplyComponent implements runtime.ComponentUpdater. When a staged manifest
// exists for the component it is published to the node (which is bind-mounted
// from the host manifests directory), its image is loaded, and the static pod is
// (re)started. Components without a staged manifest follow the regular
// enable/start path.
func (c *Cluster) ApplyComponent(ctx context.Context, name string, up bool, timeout time.Duration) error {
	logger := log.FromContext(ctx).With("component", name)

	staged := c.stagedComponentManifestPath(name)
	live := c.componentManifestPath(name)
	bak := live + ".bak"

	if _, err := os.Stat(staged); err == nil {
		// Load the image into the node. While the node is running a failure is
		// fatal; when it is stopped the image is still in the provider cache and
		// loading is retried by the regular cluster bring-up path.
		if err := c.loadComponentImage(ctx, name); err != nil {
			if up {
				return err
			}
			log.FromContext(ctx).Warn("Failed to load component image into the stopped kind node; it will be needed before starting the cluster",
				"component", name,
				"err", err,
			)
		}

		if !up {
			// Node is stopped: publish the manifest for the next start and make
			// sure no disabled copy shadows it.
			if err := os.Rename(staged, live); err != nil {
				return fmt.Errorf("failed to publish manifest for component %q: %w", name, err)
			}
			_ = os.Remove(bak)
			return nil
		}

		if _, err := os.Stat(bak); err == nil {
			// The component is currently disabled inside the node: overwrite the
			// backup and let StartComponent move it into place.
			if err := os.Rename(staged, bak); err != nil {
				return fmt.Errorf("failed to publish manifest for component %q: %w", name, err)
			}
		} else {
			// The component is running with the old manifest: replace it and let
			// the kubelet reconcile the static pod.
			if err := os.Rename(staged, live); err != nil {
				return fmt.Errorf("failed to publish manifest for component %q: %w", name, err)
			}
		}
	}

	if up {
		if err := c.StartComponent(ctx, name); err != nil {
			return err
		}
		readyTimeout := timeout
		if readyTimeout <= 0 {
			readyTimeout = 120 * time.Second
		}
		if err := c.waitComponentReady(ctx, name, true, readyTimeout); err != nil {
			return err
		}
		logger.Debug("Component is ready")
	}
	return nil
}

// RemoveComponent implements runtime.ComponentUpdater.
func (c *Cluster) RemoveComponent(ctx context.Context, name string, up bool) error {
	if up {
		if err := c.StopComponent(ctx, name); err != nil {
			return err
		}
	}

	// File-managed addon components are fully deleted so they do not come back
	// when the node starts. kubeadm-owned core components keep the .bak
	// semantics used by the existing enable/disable behavior.
	if _, managed := fileManagedComponents[name]; managed {
		if !c.IsDryRun() {
			_ = os.Remove(c.componentManifestPath(name))
			_ = os.Remove(c.componentManifestPath(name) + ".bak")
			_ = os.Remove(c.stagedComponentManifestPath(name))
		}
	}
	return nil
}

// loadComponentImage loads the component image into the kind node when needed.
func (c *Cluster) loadComponentImage(ctx context.Context, name string) error {
	component, err := c.GetComponent(ctx, name)
	if err != nil {
		return err
	}
	if component.Image == "" {
		return nil
	}

	kindPath, err := c.preDownloadKind(ctx)
	if err != nil {
		return err
	}
	conf, err := c.Config(ctx)
	if err != nil {
		return err
	}
	return c.loadImages(ctx, kindPath, []string{component.Image}, conf.Options.CacheDir)
}

func validateKindUpdate(plan *runtime.UpdatePlan) error {
	var unsupported []string
	for _, change := range plan.Changes {
		if change.Action != runtime.ComponentChangeReplace {
			continue
		}
		if _, core := coreComponents[change.Name]; core {
			unsupported = append(unsupported, change.Name)
		}
	}
	if len(unsupported) != 0 {
		return fmt.Errorf("changing parameters of the kubeadm-managed component(s) %v is not supported on the kind runtime; "+
			"enabling or disabling them is supported, recreate the cluster to apply parameter changes", unsupported)
	}
	return nil
}
