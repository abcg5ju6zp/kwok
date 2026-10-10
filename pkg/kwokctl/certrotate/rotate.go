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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"sigs.k8s.io/kwok/pkg/consts"
	"sigs.k8s.io/kwok/pkg/log"
	"sigs.k8s.io/kwok/pkg/utils/wait"
)

// Hooks contains the runtime specific actions required to rotate
// certificates. Every implementation must be safe to repeat: a resumed
// rotation calls the same hooks again from the last confirmed stage.
type Hooks interface {
	// ClusterName returns the name of the cluster.
	ClusterName() string
	// PkiDir returns the live PKI directory of the cluster.
	PkiDir() string
	// Profile returns the material profile of the runtime.
	Profile() Profile
	// ExtraSANs returns additional SANs that must be present on the new
	// serving credential.
	ExtraSANs(ctx context.Context) ([]string, error)
	// EnabledComponents returns the names of components enabled in the cluster,
	// in dependency order.
	EnabledComponents(ctx context.Context) ([]string, error)

	// SwitchComponent publishes any component specific credential material for
	// the target generation and restarts the component so that it serves the
	// new material. It must only return after the component is running again.
	SwitchComponent(ctx context.Context, name string, gen Generation) error
	// RestartComponent restarts a component without changing its credentials.
	// It is used when rolling back to the previous generation.
	RestartComponent(ctx context.Context, name string) error
	// RestoreComponent restores component specific credential material from
	// the previous generation. It is best effort and called before
	// RestartComponent during a rollback.
	RestoreComponent(ctx context.Context, name string, gen Generation) error
	// VerifyAccess verifies that the API server currently serves and accepts
	// the trust chain. Implementations must not depend on material that is
	// switched in a later stage.
	VerifyAccess(ctx context.Context) error

	// PublishClients regenerates in cluster client material (for example
	// kubeconfig files mounted into components). Files that are replaced must
	// first be backed up through BackupFiles.
	PublishClients(ctx context.Context, gen Generation) error
	// RestoreClients undoes a PublishClients call using its backup.
	RestoreClients(ctx context.Context, gen Generation) error
	// PublishKubeconfig regenerates the host kubeconfig so that the existing
	// kubeconfig keeps accessing the cluster with the new generation. Files
	// that are replaced must first be backed up through BackupFiles.
	PublishKubeconfig(ctx context.Context, gen Generation) error
	// RestoreKubeconfig undoes a PublishKubeconfig call using its backup.
	RestoreKubeconfig(ctx context.Context, gen Generation) error
}

// Rotate rotates the CA and every certificate of the cluster. If a rotation is
// already journaled on disk, the call continues that exact generation instead
// of starting a new one.
func Rotate(ctx context.Context, hooks Hooks) error {
	logger := log.FromContext(ctx)
	liveDir := hooks.PkiDir()

	if _, err := os.Stat(filepath.Join(liveDir, "ca.crt")); err != nil {
		if os.IsNotExist(err) {
			// A cluster that does not serve TLS (for example an insecure only
			// cluster) has no material to rotate; existing behavior is left
			// untouched.
			logger.Info("Cluster does not use certificates, nothing to rotate")
			return nil
		}
		return err
	}

	state, err := loadState(liveDir)
	if err != nil {
		return err
	}

	if state == nil {
		// A new rotation owns a fresh isolated area; anything left there
		// without a journal belongs to a process that died before journaling.
		if err := os.RemoveAll(rotationRoot(liveDir)); err != nil {
			return fmt.Errorf("failed to clean rotation workspace: %w", err)
		}
		state, err = newState(time.Now())
		if err != nil {
			return err
		}
		if err := saveState(liveDir, state); err != nil {
			return err
		}
	} else {
		logger.Info("Resuming certificate rotation from the last confirmed stage",
			"generation", state.Generation,
			"stage", state.Phase,
		)
	}

	gen := generationOf(liveDir, state.Generation)

	if state.Phase == PhasePreparing {
		if err := prepareGeneration(ctx, hooks, gen, state); err != nil {
			// The live cluster was never modified.
			_ = os.RemoveAll(rotationRoot(liveDir))
			return err
		}
		state.Phase = PhasePrepared
		if err := saveState(liveDir, state); err != nil {
			return err
		}
	} else {
		if err := checkResumeWorkspace(gen, state); err != nil {
			return err
		}
	}

	enabled, err := hooks.EnabledComponents(ctx)
	if err != nil {
		return err
	}

	// Stage: etcd.
	if !state.Phase.reached(PhaseEtcdSwitched) {
		targets := []string{}
		if hooks.Profile() == ProfileKind {
			targets = []string{consts.ComponentEtcd}
		}
		if err := runSwitchStage(ctx, hooks, gen, state, PhaseEtcdSwitched, etcdFiles(hooks.Profile()), targets, enabled, false); err != nil {
			return failAndRollback(ctx, hooks, gen, state, "etcd", err)
		}
	}

	// Stage: API server.
	if !state.Phase.reached(PhaseApiserverSwitched) {
		targets := []string{consts.ComponentKubeApiserver}
		if err := runSwitchStage(ctx, hooks, gen, state, PhaseApiserverSwitched, mainFiles(hooks.Profile()), targets, enabled, true); err != nil {
			return failAndRollback(ctx, hooks, gen, state, "kube-apiserver", err)
		}
	}

	// Stage: controllers and every other in cluster component that consumes
	// the trust material.
	if !state.Phase.reached(PhaseControllersSwitched) {
		targets := controllerTargets(enabled)
		if err := runSwitchStage(ctx, hooks, gen, state, PhaseControllersSwitched, nil, targets, enabled, false); err != nil {
			return failAndRollback(ctx, hooks, gen, state, "controllers", err)
		}
	}

	// Stage: in cluster client material. From here onwards a failure only
	// rolls back the unfinished publishing step; components already run the
	// new generation and must not be switched again.
	if !state.Phase.reached(PhaseClientsSwitched) {
		if err := hooks.PublishClients(ctx, gen); err != nil {
			restorePublishing(ctx, hooks.RestoreClients, gen, "client material")
			return failResumePublishing(state, "client material", err)
		}
		state.Phase = PhaseClientsSwitched
		if err := saveState(liveDir, state); err != nil {
			return err
		}
	}

	// Stage: host kubeconfig and final verification.
	if !state.Phase.reached(PhaseKubeconfigPublished) {
		if err := hooks.PublishKubeconfig(ctx, gen); err != nil {
			restorePublishing(ctx, hooks.RestoreKubeconfig, gen, "kubeconfig")
			return failResumePublishing(state, "kubeconfig", err)
		}
		if err := pollVerifyAccess(ctx, hooks); err != nil {
			restorePublishing(ctx, hooks.RestoreKubeconfig, gen, "kubeconfig")
			return failResumePublishing(state, "kubeconfig", err)
		}
		state.Phase = PhaseKubeconfigPublished
		if err := saveState(liveDir, state); err != nil {
			return err
		}
	}

	// Finalize: the new chain has been verified end to end, so the previous
	// generation and the journal are removed and only the target generation
	// remains on disk.
	if err := os.RemoveAll(rotationRoot(liveDir)); err != nil {
		return fmt.Errorf("rotation %s completed but the old material could not be removed: %w; rerun to finish", state.Generation, err)
	}

	logger.Info("Certificate rotation completed",
		"generation", state.Generation,
	)
	return nil
}

// components that are restarted in the controllers stage. etcd and the API
// server are switched in their own stages; the insecure proxy does not use the
// trust material.
var controllerStageExcluded = map[string]struct{}{
	consts.ComponentEtcd:                       {},
	consts.ComponentKubeApiserver:              {},
	consts.ComponentKubeApiserverInsecureProxy: {},
}

func controllerTargets(enabled []string) []string {
	targets := make([]string, 0, len(enabled))
	for _, name := range enabled {
		if _, ok := controllerStageExcluded[name]; ok {
			continue
		}
		targets = append(targets, name)
	}
	return targets
}

// generateMaterialFn and validateMaterialFn are seams so tests can simulate
// preparation failures without touching the live cluster.
var (
	generateMaterialFn = GenerateMaterial
	validateMaterialFn = ValidateMaterial
)

func prepareGeneration(ctx context.Context, hooks Hooks, gen Generation, state *State) error {
	if err := os.MkdirAll(gen.NewDir, 0o755); err != nil {
		return fmt.Errorf("failed to create isolated material directory: %w", err)
	}
	if err := os.MkdirAll(gen.OldDir, 0o755); err != nil {
		return fmt.Errorf("failed to create backup material directory: %w", err)
	}

	sans, err := hooks.ExtraSANs(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect certificate SANs: %w", err)
	}
	state.SANs = sans

	// Snapshot the current, working generation before anything is generated.
	// This only reads the live directory.
	if _, err := backupLiveMaterial(gen.LiveDir, gen.OldDir); err != nil {
		return fmt.Errorf("failed to snapshot the current material: %w", err)
	}

	if err := generateMaterialFn(ctx, gen.NewDir, hooks.Profile(), hooks.ClusterName(), sans, gen.LiveDir); err != nil {
		return fmt.Errorf("failed to generate new material: %w", err)
	}
	if err := validateMaterialFn(gen.NewDir, hooks.Profile(), gen.LiveDir, time.Now()); err != nil {
		return fmt.Errorf("new material failed validation: %w", err)
	}
	return nil
}

func checkResumeWorkspace(gen Generation, state *State) error {
	if _, err := os.Stat(gen.Root); err != nil {
		return fmt.Errorf("cannot resume rotation %s: isolated directory %s is gone: %w", state.Generation, gen.Root, err)
	}
	if state.Phase.reached(PhaseEtcdSwitched) {
		if _, err := os.Stat(gen.OldDir); err != nil {
			return fmt.Errorf("cannot resume rotation %s: previous generation backup %s is gone: %w; refusing to continue without rollback material", state.Generation, gen.OldDir, err)
		}
	}
	return nil
}

// runSwitchStage publishes files to the live PKI directory and switches the
// given components one by one, journaling every confirmed component.
func runSwitchStage(ctx context.Context, hooks Hooks, gen Generation, state *State, phase Phase, files, targets, enabled []string, verify bool) error {
	liveDir := hooks.PkiDir()

	enabledSet := map[string]struct{}{}
	for _, name := range enabled {
		enabledSet[name] = struct{}{}
	}

	if len(files) != 0 {
		if err := publishMaterial(gen.NewDir, liveDir, files); err != nil {
			return err
		}
	}

	for _, name := range targets {
		if _, ok := enabledSet[name]; !ok {
			// Disabled components do not have to be switched.
			continue
		}
		if slices.Contains(state.SwitchedComponents, name) {
			// Confirmed by an earlier run of this generation; never switch twice.
			continue
		}
		state.SwitchedComponents = append(state.SwitchedComponents, name)
		if err := saveState(liveDir, state); err != nil {
			return err
		}
		if err := hooks.SwitchComponent(ctx, name, gen); err != nil {
			return fmt.Errorf("component %s rejected the new generation: %w", name, err)
		}
	}

	if verify {
		if err := pollVerifyAccess(ctx, hooks); err != nil {
			return err
		}
	}

	state.Phase = phase
	return saveState(liveDir, state)
}

func pollVerifyAccess(ctx context.Context, hooks Hooks) error {
	var lastErr error
	err := wait.Poll(ctx, func(ctx context.Context) (bool, error) {
		lastErr = hooks.VerifyAccess(ctx)
		return lastErr == nil, nil
	},
		wait.WithTimeout(2*time.Minute),
		wait.WithInterval(time.Second),
		wait.WithImmediate(),
	)
	if err != nil {
		if lastErr != nil {
			return fmt.Errorf("the new trust chain is not served: %w", lastErr)
		}
		return err
	}
	return nil
}

// failAndRollback restores the previous generation after a component switch
// failed and removes the rotation workspace, so that the next request starts
// a fresh rotation against the restored cluster.
func failAndRollback(ctx context.Context, hooks Hooks, gen Generation, state *State, stage string, cause error) error {
	logger := log.FromContext(ctx)
	logger.Error("Certificate rotation failed, restoring the previous generation",
		"stage", stage,
		"generation", state.Generation,
		"err", cause,
	)

	if err := restoreMaterial(gen.OldDir, gen.LiveDir); err != nil {
		return errors.Join(
			fmt.Errorf("rotation failed at stage %s: %w", stage, cause),
			fmt.Errorf("restoring the previous generation failed: %w", err),
		)
	}

	var rollbackErr error
	for i := len(state.SwitchedComponents) - 1; i >= 0; i-- {
		name := state.SwitchedComponents[i]
		if err := hooks.RestoreComponent(ctx, name, gen); err != nil {
			logger.Warn("Failed to restore component credentials",
				"component", name,
				"err", err,
			)
		}
		if err := hooks.RestartComponent(ctx, name); err != nil {
			logger.Error("Failed to restart component with the previous generation",
				"component", name,
				"err", err,
			)
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}

	if err := hooks.VerifyAccess(ctx); err != nil {
		logger.Warn("Cluster is not serving yet after rolling back the certificate rotation",
			"err", err,
		)
	}

	if rollbackErr != nil {
		// Keep the journal so the next request can retry the rollback.
		return errors.Join(fmt.Errorf("rotation failed at stage %s: %w", stage, cause), rollbackErr)
	}

	if err := os.RemoveAll(rotationRoot(gen.LiveDir)); err != nil {
		logger.Warn("Failed to remove rotation workspace",
			"err", err,
		)
	}
	return cause
}

func restorePublishing(ctx context.Context, restore func(context.Context, Generation) error, gen Generation, what string) {
	logger := log.FromContext(ctx)
	if err := restore(ctx, gen); err != nil {
		logger.Error("Failed to roll back %s publishing",
			"what", what,
			"err", err,
		)
	}
}

// failResumePublishing returns the error without removing the journal: the
// component switches are already confirmed, so rerunning the rotation only
// retries the unfinished publishing step.
func failResumePublishing(state *State, what string, cause error) error {
	return fmt.Errorf("rotation %s failed while publishing %s: %w (rerun to resume from this step; switched components are not touched again)", state.Generation, what, cause)
}
