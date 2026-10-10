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

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/kwok/pkg/apis/internalversion"
	"sigs.k8s.io/kwok/pkg/config"
	"sigs.k8s.io/kwok/pkg/consts"
	"sigs.k8s.io/kwok/pkg/kwokctl/components"
	"sigs.k8s.io/kwok/pkg/log"
	"sigs.k8s.io/kwok/pkg/utils/file"
	"sigs.k8s.io/kwok/pkg/utils/flock"
	utilsslices "sigs.k8s.io/kwok/pkg/utils/slices"
	"sigs.k8s.io/kwok/pkg/utils/wait"
	"sigs.k8s.io/kwok/pkg/utils/yaml"
)

// UpdateStateName is the name of the component update transaction state file,
// which lives in the cluster work directory.
const UpdateStateName = "update-state.yaml"

// updateLockName is the advisory lock serializing component updates.
const updateLockName = "update.lock"

// ComponentChangeAction describes what happens to a component during an update.
type ComponentChangeAction string

const (
	// ComponentChangeStart means the component is newly enabled and will be installed and started.
	ComponentChangeStart ComponentChangeAction = "start"
	// ComponentChangeStop means the component is disabled and will be stopped and removed.
	ComponentChangeStop ComponentChangeAction = "stop"
	// ComponentChangeReplace means the component stays enabled but its resources or parameters change.
	ComponentChangeReplace ComponentChangeAction = "replace"
)

// ComponentChange is a single planned change between the current and the target component graph.
type ComponentChange struct {
	// Name is the component name.
	Name string
	// Action is the planned action.
	Action ComponentChangeAction
	// Before is the current rendered component, nil for start actions.
	Before *internalversion.Component
	// After is the target rendered component, nil for stop actions.
	After *internalversion.Component
}

// UpdatePlan describes the actual changes that an update will apply.
type UpdatePlan struct {
	// Changes holds all planned changes in execution order (stops first, then starts/replaces).
	Changes []ComponentChange

	// groups are the dependency groups over the union of the current and target graphs.
	groups [][]internalversion.Component
	// byName indexes changes by component name.
	byName map[string]ComponentChange
}

// StopComponents returns the names of the components that will be stopped, in stop order.
func (p *UpdatePlan) StopComponents() []string { return p.namesByAction(ComponentChangeStop) }

// StartComponents returns the names of the components that will be started, in start order.
func (p *UpdatePlan) StartComponents() []string { return p.namesByAction(ComponentChangeStart) }

// ReplaceComponents returns the names of the components that will be replaced, in apply order.
func (p *UpdatePlan) ReplaceComponents() []string { return p.namesByAction(ComponentChangeReplace) }

func (p *UpdatePlan) namesByAction(action ComponentChangeAction) []string {
	var names []string
	for _, change := range p.Changes {
		if change.Action == action {
			names = append(names, change.Name)
		}
	}
	return names
}

// UpdateComponentsOptions configures a component update transaction.
type UpdateComponentsOptions struct {
	// Target is the desired cluster configuration. Its Options describe the new
	// enabled/disabled sets and component parameters; its Components field is
	// rebuilt by the runtime during preflight.
	Target *internalversion.KwokctlConfiguration
	// WaitTimeout bounds how long each replaced or started component may take to
	// become ready. Zero disables readiness waiting.
	WaitTimeout time.Duration
}

// ComponentUpdater is implemented by runtimes that can reconcile the components of
// an existing cluster. It is the runtime-specific side of the generic update
// transaction implemented by UpdateClusterComponents.
//
// Implementations MUST make all three operations idempotent so that a
// transaction interrupted by a process exit can be resumed safely.
type ComponentUpdater interface {
	// RenderComponents renders conf.Components from conf.Options (including
	// component patches), ensures the binaries, images and manifests required by
	// the configuration are available (in the download cache) and stages or
	// writes all component support files. It MUST NOT start, stop or otherwise
	// reconfigure any running component. It returns the fully rendered
	// configuration (including allocated ports and component specifications).
	RenderComponents(ctx context.Context, conf *internalversion.KwokctlConfiguration) (*internalversion.KwokctlConfiguration, error)

	// ApplyComponent installs or replaces the runtime resource (process,
	// container or static pod manifest) of the component described by the active
	// configuration and, when the cluster is up, starts it and waits for it to be
	// ready within timeout.
	ApplyComponent(ctx context.Context, name string, up bool, timeout time.Duration) error

	// RemoveComponent stops (when the cluster is up) and removes the runtime
	// resource of a disabled component.
	RemoveComponent(ctx context.Context, name string, up bool) error
}

// ComponentUpdateValidator is an optional runtime hook enforcing runtime
// specific update constraints. A returned error aborts the update before any
// component is changed.
type ComponentUpdateValidator interface {
	ValidateUpdate(ctx context.Context, plan *UpdatePlan, target *internalversion.KwokctlConfiguration) error
}

// UpdateClusterComponents updates the auxiliary components and their parameters of
// an existing cluster without recreating it.
//
// It renders the target configuration, compares the current and target component
// dependency graphs, validates the target preconditions, then applies the changes
// as a journaled transaction: failures roll back in reverse order and a process
// interrupted mid-update resumes the same transaction on the next invocation.
// The on-disk cluster configuration is only rewritten once every target
// component is available.
func UpdateClusterComponents(ctx context.Context, rt Runtime, opts UpdateComponentsOptions) (*UpdatePlan, error) {
	if opts.Target == nil {
		return nil, fmt.Errorf("target configuration is required")
	}

	updater, ok := rt.(ComponentUpdater)
	if !ok {
		return nil, fmt.Errorf("runtime does not support updating components")
	}

	// Serialize concurrent updates against the same cluster.
	lock, err := acquireUpdateLock(rt)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = releaseUpdateLock(lock)
	}()

	// Resume a transaction interrupted by a previous process exit instead of
	// starting a new one from the uncommitted configuration.
	journalPath := rt.GetWorkdirPath(UpdateStateName)
	if journal, ok, err := loadUpdateJournal(journalPath); err != nil {
		return nil, fmt.Errorf("failed to load update state %s: %w", journalPath, err)
	} else if ok {
		logger := log.FromContext(ctx)
		logger.Warn("Resuming interrupted component update")
		return resumeUpdate(ctx, rt, updater, journal, opts.WaitTimeout)
	}

	return startUpdate(ctx, rt, updater, opts, journalPath)
}

func startUpdate(ctx context.Context, rt Runtime, updater ComponentUpdater, opts UpdateComponentsOptions, journalPath string) (*UpdatePlan, error) {
	logger := log.FromContext(ctx)

	origin, err := rt.Config(ctx)
	if err != nil {
		return nil, err
	}
	origin = origin.DeepCopy()

	target := opts.Target.DeepCopy()
	target.Components = nil

	// Render the target component graph. This only touches the download cache and
	// staged/support files, never running components.
	rendered, err := updater.RenderComponents(ctx, target)
	if err != nil {
		// Rendering may have overwritten deterministic support files; regenerate
		// the committed ones so the workdir stays consistent with the running state.
		restoreRenderedFiles(ctx, updater, origin)
		return nil, fmt.Errorf("failed to prepare target components: %w", err)
	}
	target = rendered

	plan, err := BuildUpdatePlan(origin.Components, target.Components)
	if err != nil {
		restoreRenderedFiles(ctx, updater, origin)
		return nil, err
	}

	if validator, ok := rt.(ComponentUpdateValidator); ok {
		if err := validator.ValidateUpdate(ctx, plan, target); err != nil {
			restoreRenderedFiles(ctx, updater, origin)
			return nil, err
		}
	}

	if err := preflightUpdate(ctx, rt, origin.Components, target); err != nil {
		restoreRenderedFiles(ctx, updater, origin)
		return nil, err
	}

	logPlan(logger, plan)

	if len(plan.Changes) == 0 {
		logger.Info("Components are already up to date")
		return plan, nil
	}

	if rt.IsDryRun() {
		return plan, nil
	}

	up := clusterIsUp(ctx, rt, origin)

	journal, err := newUpdateJournal(origin, target, plan, up)
	if err != nil {
		return nil, err
	}
	journal.Phase = updatePhaseApplying
	if err := journal.save(journalPath); err != nil {
		return nil, err
	}

	plan, applyErr := applyUpdate(ctx, rt, updater, journal, plan, opts.WaitTimeout)
	if applyErr != nil {
		logger.Error("Failed to update components, rolling back",
			"err", applyErr,
		)
		rollbackErr := rollbackUpdate(ctx, rt, updater, journal, opts.WaitTimeout)
		if rollbackErr != nil {
			return plan, errors.Join(
				fmt.Errorf("update failed: %w", applyErr),
				fmt.Errorf("rollback failed, the cluster will resume the transaction on the next invocation: %w", rollbackErr),
			)
		}
		return plan, fmt.Errorf("update failed and changes were rolled back: %w", applyErr)
	}

	if err := commitUpdate(ctx, rt, target, journal, journalPath, opts.WaitTimeout); err != nil {
		return plan, err
	}

	logger.Info("Component update completed")
	return plan, nil
}

// componentSpecHash returns a stable representation of the component runtime spec.
// Two components with equal specs require no replacement.
func componentSpecHash(component internalversion.Component) string {
	data, err := json.Marshal(component)
	if err != nil {
		// All fields are plain JSON-serializable types; a marshal error here is a programming bug.
		return component.Name + "#unhashable"
	}
	return string(data)
}

// BuildUpdatePlan compares the current and target rendered component sets and
// builds the ordered change plan over the union dependency graph. Components
// present in both sets with identical runtime specs are left untouched.
func BuildUpdatePlan(old, new []internalversion.Component) (*UpdatePlan, error) {
	oldByName := map[string]internalversion.Component{}
	for _, component := range old {
		oldByName[component.Name] = component
	}
	newByName := map[string]internalversion.Component{}
	for _, component := range new {
		if _, dup := newByName[component.Name]; dup {
			return nil, fmt.Errorf("duplicated component %q in target configuration", component.Name)
		}
		newByName[component.Name] = component
	}

	changes := make([]ComponentChange, 0)
	byName := map[string]ComponentChange{}
	record := func(change ComponentChange) {
		byName[change.Name] = change
		changes = append(changes, change)
	}

	for _, component := range new {
		oldComponent, ok := oldByName[component.Name]
		if !ok {
			c := component
			record(ComponentChange{Name: component.Name, Action: ComponentChangeStart, After: &c})
			continue
		}
		if componentSpecHash(oldComponent) != componentSpecHash(component) {
			oldC, newC := oldComponent, component
			record(ComponentChange{Name: component.Name, Action: ComponentChangeReplace, Before: &oldC, After: &newC})
		}
	}
	for _, component := range old {
		if _, ok := newByName[component.Name]; !ok {
			c := component
			record(ComponentChange{Name: component.Name, Action: ComponentChangeStop, Before: &c})
		}
	}

	// Validate the target dependency graph on its own.
	if _, err := components.GroupByLinks(new); err != nil {
		return nil, err
	}

	// Build the union graph so changes can be ordered by dependency. Current-only
	// components keep their links; every link in the union resolves inside it.
	union := make([]internalversion.Component, 0, len(old)+len(new))
	union = append(union, new...)
	for _, component := range old {
		if _, ok := newByName[component.Name]; !ok {
			union = append(union, component)
		}
	}
	groups, err := components.GroupByLinks(union)
	if err != nil {
		return nil, err
	}

	// Order the change list: stops (reverse dependency order) first, then starts
	// and replaces in dependency order.
	ordered := make([]ComponentChange, 0, len(changes))
	for i := len(groups) - 1; i >= 0; i-- {
		for _, component := range groups[i] {
			if change, ok := byName[component.Name]; ok && change.Action == ComponentChangeStop {
				ordered = append(ordered, change)
			}
		}
	}
	for _, group := range groups {
		for _, component := range group {
			if change, ok := byName[component.Name]; ok && change.Action != ComponentChangeStop {
				ordered = append(ordered, change)
			}
		}
	}

	return &UpdatePlan{
		Changes: ordered,
		groups:  groups,
		byName:  byName,
	}, nil
}

// preflightUpdate validates that the target components can actually run before
// anything is changed: mandatory components, dependency graph, host ports and
// host path volumes. Binaries, images and manifests are ensured while rendering.
func preflightUpdate(ctx context.Context, rt Runtime, old []internalversion.Component, target *internalversion.KwokctlConfiguration) error {
	var problems []string

	hasComponent := func(name string) bool {
		_, ok := utilsslices.Find(target.Components, func(component internalversion.Component) bool {
			return component.Name == name
		})
		return ok
	}
	if !hasComponent(consts.ComponentEtcd) {
		problems = append(problems, "etcd must be enabled")
	}
	if !hasComponent(consts.ComponentKubeApiserver) {
		problems = append(problems, "kube-apiserver must be enabled")
	}

	// Ports declared by other, untouched clusters stay reserved. Ports already
	// served by this cluster are allowed to remain reserved (unchanged components
	// keep holding them); only newly claimed host ports are bind-checked.
	oldHostPorts := map[uint32]struct{}{}
	for _, component := range old {
		for _, port := range component.Ports {
			if port.HostPort != 0 {
				oldHostPorts[port.HostPort] = struct{}{}
			}
		}
	}
	claimedByOthers := GetUsedPorts(ctx)
	targetPorts := map[uint32]struct{}{}
	for _, component := range target.Components {
		for _, port := range component.Ports {
			if port.HostPort == 0 {
				continue
			}
			if _, ok := targetPorts[port.HostPort]; ok {
				problems = append(problems, fmt.Sprintf("duplicated host port %d among target components", port.HostPort))
				continue
			}
			targetPorts[port.HostPort] = struct{}{}
			if _, kept := oldHostPorts[port.HostPort]; kept {
				continue
			}
			if claimedByOthers.Has(port.HostPort) {
				problems = append(problems, fmt.Sprintf("host port %d required by component %q is already declared by another cluster", port.HostPort, component.Name))
				continue
			}
			if !portAvailable(port.HostPort) {
				problems = append(problems, fmt.Sprintf("host port %d required by component %q is already in use", port.HostPort, component.Name))
			}
		}
	}

	// Volumes: ensure the declared host paths satisfy their PathType contract.
	seenVolumes := map[string]struct{}{}
	for _, component := range target.Components {
		for _, volume := range component.Volumes {
			if volume.HostPath == "" {
				continue
			}
			if _, ok := seenVolumes[volume.HostPath]; ok {
				continue
			}
			seenVolumes[volume.HostPath] = struct{}{}
			if err := checkVolumeHostPath(rt.IsDryRun(), volume); err != nil {
				problems = append(problems, fmt.Sprintf("component %q: %v", component.Name, err))
			}
		}
	}

	if len(problems) != 0 {
		return fmt.Errorf("preflight check failed:\n  - %s", joinLines(problems))
	}
	return nil
}

func joinLines(lines []string) string {
	result := ""
	for i, line := range lines {
		if i != 0 {
			result += "\n  - "
		}
		result += line
	}
	return result
}

func portAvailable(port uint32) bool {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

func checkVolumeHostPath(dryRun bool, volume internalversion.Volume) error {
	switch volume.PathType {
	case internalversion.HostPathDirectoryOrCreate:
		if file.Exists(volume.HostPath) {
			return nil
		}
		if dryRun {
			return nil
		}
		if err := os.MkdirAll(volume.HostPath, 0o755); err != nil {
			return fmt.Errorf("failed to create volume host directory %q: %w", volume.HostPath, err)
		}
	case internalversion.HostPathFileOrCreate:
		if file.Exists(volume.HostPath) {
			return nil
		}
		if dryRun {
			return nil
		}
		if err := file.Create(volume.HostPath); err != nil {
			return fmt.Errorf("failed to create volume host file %q: %w", volume.HostPath, err)
		}
	case internalversion.HostPathDirectory:
		info, err := os.Stat(volume.HostPath)
		if err != nil {
			return fmt.Errorf("volume host path %q must be an existing directory: %w", volume.HostPath, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("volume host path %q must be a directory", volume.HostPath)
		}
	case internalversion.HostPathFile:
		info, err := os.Stat(volume.HostPath)
		if err != nil {
			return fmt.Errorf("volume host path %q must be an existing file: %w", volume.HostPath, err)
		}
		if info.IsDir() {
			return fmt.Errorf("volume host path %q must not be a directory", volume.HostPath)
		}
	case internalversion.HostPathSocket, internalversion.HostPathCharDev, internalversion.HostPathBlockDev:
		if !file.Exists(volume.HostPath) {
			return fmt.Errorf("volume host path %q of type %q must exist", volume.HostPath, volume.PathType)
		}
	case internalversion.HostPathUnset:
		// No contract to enforce.
	}
	return nil
}

// clusterIsUp reports whether the essential control plane components are running.
func clusterIsUp(ctx context.Context, rt Runtime, conf *internalversion.KwokctlConfiguration) bool {
	essential := []string{consts.ComponentEtcd, consts.ComponentKubeApiserver}
	for _, name := range essential {
		if _, err := rt.GetComponent(ctx, name); err != nil {
			return false
		}
		status, err := rt.InspectComponent(ctx, name)
		if err != nil {
			return false
		}
		if status != ComponentStatusRunning && status != ComponentStatusReady {
			return false
		}
	}
	return true
}

// waitComponentReady polls the component status until it is ready or the timeout elapses.
func waitComponentReady(ctx context.Context, rt Runtime, name string, timeout time.Duration) error {
	if timeout <= 0 || rt.IsDryRun() {
		return nil
	}
	logger := log.FromContext(ctx).With("component", name)
	var (
		err     error
		waitErr error
		ready   bool
	)
	waitErr = wait.Poll(ctx, func(ctx context.Context) (bool, error) {
		status, inspectErr := rt.InspectComponent(ctx, name)
		if inspectErr != nil {
			err = inspectErr
			logger.Debug("Component is not ready yet",
				"err", inspectErr,
			)
			return false, nil
		}
		ready = status == ComponentStatusReady
		if !ready {
			err = nil
			logger.Debug("Component is not ready yet",
				"status", status,
			)
		}
		return ready, nil
	},
		wait.WithTimeout(timeout),
		wait.WithContinueOnError(10),
		wait.WithInterval(time.Second/2),
		wait.WithImmediate(),
	)
	if waitErr != nil {
		if err != nil {
			return fmt.Errorf("component %q did not become ready: %w (last error: %v)", name, waitErr, err)
		}
		return fmt.Errorf("component %q did not become ready: %w", name, waitErr)
	}
	return nil
}

func logPlan(logger *log.Logger, plan *UpdatePlan) {
	if len(plan.Changes) == 0 {
		return
	}
	for _, change := range plan.Changes {
		switch change.Action {
		case ComponentChangeStop:
			logger.Info("Component will be stopped",
				"component", change.Name,
			)
		case ComponentChangeStart:
			logger.Info("Component will be started",
				"component", change.Name,
			)
		case ComponentChangeReplace:
			logger.Info("Component will be replaced",
				"component", change.Name,
			)
		}
	}
}

func restoreRenderedFiles(ctx context.Context, updater ComponentUpdater, origin *internalversion.KwokctlConfiguration) {
	conf := origin.DeepCopy()
	conf.Components = nil
	// Best effort: regenerate deterministic support files of the committed config.
	// Failures here do not affect the running cluster and the on-disk declaration,
	// which is left untouched.
	_, _ = updater.RenderComponents(ctx, conf)
}

// --- transaction phases ---

const (
	updatePhaseApplying    = "applying"
	updatePhaseCommitting  = "committing"
	updatePhaseRollingBack = "rollingback"
)

const (
	stepStopComponent   = "stop"
	stepRemoveComponent = "remove"
	stepApplyComponent  = "apply"
	stepInitCRs         = "crs"
)

// applyUpdate executes the forward sweep. It is idempotent: already completed
// steps recorded in the journal are skipped, which makes resume safe.
func applyUpdate(ctx context.Context, rt Runtime, updater ComponentUpdater, journal *updateJournal, plan *UpdatePlan, timeout time.Duration) (*UpdatePlan, error) {
	up := journal.Up
	done := map[string]struct{}{}
	for _, step := range journal.Done {
		done[step] = struct{}{}
	}
	mark := func(step string) error {
		if _, ok := done[step]; ok {
			return nil
		}
		done[step] = struct{}{}
		journal.Done = append(journal.Done, step)
		return journal.save(rt.GetWorkdirPath(UpdateStateName))
	}

	// Set the active configuration to the target so the runtime primitives
	// (StartComponent, container creation, ...) use the new specifications.
	if err := rt.SetConfig(ctx, journal.target()); err != nil {
		return plan, err
	}

	logger := log.FromContext(ctx)

	// Sweep A, reverse dependency order: stop components that are removed or
	// replaced, then tear down resources of removed ones.
	for i := len(plan.groups) - 1; i >= 0; i-- {
		for _, component := range plan.groups[i] {
			change, ok := plan.byName[component.Name]
			if !ok {
				continue
			}
			if change.Action != ComponentChangeStop && change.Action != ComponentChangeReplace {
				continue
			}
			stopKey := fmt.Sprintf("%s:%s", stepStopComponent, change.Name)
			if _, finished := done[stopKey]; !finished {
				if up {
					logger.Info("Stopping component",
						"component", change.Name,
					)
					if err := rt.StopComponent(ctx, change.Name); err != nil {
						return plan, fmt.Errorf("failed to stop component %q: %w", change.Name, err)
					}
				}
				if err := mark(stopKey); err != nil {
					return plan, err
				}
			}
			if change.Action == ComponentChangeStop {
				removeKey := fmt.Sprintf("%s:%s", stepRemoveComponent, change.Name)
				if _, finished := done[removeKey]; !finished {
					if err := updater.RemoveComponent(ctx, change.Name, up); err != nil {
						return plan, fmt.Errorf("failed to remove component %q: %w", change.Name, err)
					}
					if err := mark(removeKey); err != nil {
						return plan, err
					}
				}
			}
		}
	}

	// Sweep B, dependency order: install/replace resources and start, waiting for
	// every component to become ready before moving on to its dependents.
	for _, group := range plan.groups {
		for _, component := range group {
			change, ok := plan.byName[component.Name]
			if !ok {
				continue
			}
			if change.Action != ComponentChangeStart && change.Action != ComponentChangeReplace {
				continue
			}
			applyKey := fmt.Sprintf("%s:%s", stepApplyComponent, change.Name)
			if _, finished := done[applyKey]; !finished {
				logger.Info("Applying component",
					"component", change.Name,
					"action", change.Action,
				)
				if err := updater.ApplyComponent(ctx, change.Name, up, timeout); err != nil {
					return plan, fmt.Errorf("failed to apply component %q: %w", change.Name, err)
				}
				if up {
					if err := waitComponentReady(ctx, rt, change.Name, timeout); err != nil {
						return plan, err
					}
				}
				if err := mark(applyKey); err != nil {
					return plan, err
				}
			}
		}
	}

	// Apply the Kubernetes manifests (e.g. in-cluster deployments) carried by the
	// target components. Unrelated Kubernetes resources are never deleted.
	crsKey := stepInitCRs
	if _, finished := done[crsKey]; !finished {
		if err := rt.InitCRs(ctx); err != nil {
			return plan, fmt.Errorf("failed to apply component manifests: %w", err)
		}
		if err := mark(crsKey); err != nil {
			return plan, err
		}
	}

	return plan, nil
}

// rollbackUpdate restores, in reverse order, every component and resource changed
// during the failed forward sweep.
func rollbackUpdate(ctx context.Context, rt Runtime, updater ComponentUpdater, journal *updateJournal, timeout time.Duration) error {
	journal.Phase = updatePhaseRollingBack
	if err := journal.save(rt.GetWorkdirPath(UpdateStateName)); err != nil {
		return err
	}

	origin := journal.origin()
	// Regenerate the component specifications, support files and staged
	// manifests of the committed configuration.
	renderedOrigin, err := updater.RenderComponents(ctx, origin)
	if err != nil {
		return fmt.Errorf("failed to prepare rollback resources: %w", err)
	}
	origin = renderedOrigin
	if err := rt.SetConfig(ctx, origin); err != nil {
		return err
	}

	actions := map[string]ComponentChangeAction{}
	for _, action := range journal.Actions {
		actions[action.Name] = action.Action
	}

	logger := log.FromContext(ctx)
	finished := map[string]struct{}{}
	for _, step := range journal.RolledBack {
		finished[step] = struct{}{}
	}
	mark := func(step string) error {
		if _, ok := finished[step]; ok {
			return nil
		}
		finished[step] = struct{}{}
		journal.RolledBack = append(journal.RolledBack, step)
		return journal.save(rt.GetWorkdirPath(UpdateStateName))
	}

	done := journal.Done
	for i := len(done) - 1; i >= 0; i-- {
		step := done[i]
		kind, name, parsed := parseStep(step)
		if !parsed {
			if step == stepInitCRs {
				// Best effort restore of the committed manifests.
				if err := rt.InitCRs(ctx); err != nil {
					logger.Warn("Failed to reapply committed manifests during rollback",
						"err", err,
					)
				}
				if err := mark(step); err != nil {
					return err
				}
			}
			continue
		}

		switch kind {
		case stepApplyComponent:
			action := actions[name]
			if action == ComponentChangeStart {
				// A newly added component: undo it entirely.
				if err := updater.RemoveComponent(ctx, name, journal.Up); err != nil {
					return fmt.Errorf("rollback: failed to remove component %q: %w", name, err)
				}
			} else {
				// A replaced component: bring the previous specification back.
				logger.Info("Restoring component",
					"component", name,
				)
				if err := updater.ApplyComponent(ctx, name, journal.Up, timeout); err != nil {
					return fmt.Errorf("rollback: failed to restore component %q: %w", name, err)
				}
				if journal.Up {
					if err := waitComponentReady(ctx, rt, name, timeout); err != nil {
						return err
					}
				}
			}
		case stepRemoveComponent:
			// A removed component: recreate it from the committed configuration.
			logger.Info("Restoring component",
				"component", name,
			)
			if err := updater.ApplyComponent(ctx, name, journal.Up, timeout); err != nil {
				return fmt.Errorf("rollback: failed to restore component %q: %w", name, err)
			}
			if journal.Up {
				if err := waitComponentReady(ctx, rt, name, timeout); err != nil {
					return err
				}
			}
		case stepStopComponent:
			if actions[name] == ComponentChangeStart {
				// A newly added component was only stopped because its apply step
				// failed; the inverse apply step above already removed it.
				continue
			}
			inverseStep := stepApplyComponent + ":" + name
			if actions[name] == ComponentChangeStop {
				inverseStep = stepRemoveComponent + ":" + name
			}
			if _, restored := finished[inverseStep]; restored {
				// The component was already brought back while undoing the inverse
				// forward step.
				continue
			}
			// A replaced component (or a removed component whose apply inverse
			// was not reached) must be brought back from the committed
			// configuration. This is idempotent with prior inverse steps.
			logger.Info("Restoring component",
				"component", name,
			)
			if err := updater.ApplyComponent(ctx, name, journal.Up, timeout); err != nil {
				return fmt.Errorf("rollback: failed to restore component %q: %w", name, err)
			}
			if journal.Up {
				if err := waitComponentReady(ctx, rt, name, timeout); err != nil {
					return err
				}
			}
		}
		if err := mark(step); err != nil {
			return err
		}
	}

	// All running state matches the committed on-disk configuration again; drop
	// the recovery state.
	if err := rt.SetConfig(ctx, origin); err != nil {
		return err
	}
	return os.Remove(rt.GetWorkdirPath(UpdateStateName))
}

// commitUpdate switches the on-disk declaration to the now-running target
// configuration and clears the recovery state. If saving fails, the transaction
// is either rolled back or left recoverable for the next invocation.
func commitUpdate(ctx context.Context, rt Runtime, target *internalversion.KwokctlConfiguration, journal *updateJournal, journalPath string, timeout time.Duration) error {
	if err := rt.SetConfig(ctx, target); err != nil {
		return err
	}
	journal.Phase = updatePhaseCommitting
	if err := journal.save(journalPath); err != nil {
		return err
	}

	if err := rt.Save(ctx); err != nil {
		// Try to converge the running state back to the on-disk declaration. If
		// that fails too, keep the recovery state so a later invocation retries
		// the commit instead of starting from the uncommitted configuration.
		if rollbackErr := rollbackUpdate(ctx, rt, rt.(ComponentUpdater), journal, timeout); rollbackErr != nil {
			return errors.Join(
				fmt.Errorf("failed to save cluster configuration: %w", err),
				fmt.Errorf("rollback failed; the update can be resumed: %w", rollbackErr),
			)
		}
		return fmt.Errorf("failed to save cluster configuration, changes rolled back: %w", err)
	}

	return os.Remove(journalPath)
}

// resumeUpdate continues an interrupted transaction according to its recorded phase.
func resumeUpdate(ctx context.Context, rt Runtime, updater ComponentUpdater, journal *updateJournal, timeout time.Duration) (*UpdatePlan, error) {
	origin := journal.origin()
	target := journal.target()

	switch journal.Phase {
	case updatePhaseCommitting:
		// All changes were applied; just finish the durable commit.
		if err := commitUpdate(ctx, rt, target, journal, rt.GetWorkdirPath(UpdateStateName), timeout); err != nil {
			return nil, err
		}
		return &UpdatePlan{Changes: journal.changes()}, nil
	case updatePhaseRollingBack:
		if err := rollbackUpdate(ctx, rt, updater, journal, timeout); err != nil {
			return nil, fmt.Errorf("failed to finish rollback: %w", err)
		}
		return nil, fmt.Errorf("the interrupted update had been rolled back")
	}

	// phase applying (or any unknown value): continue the forward sweep.
	plan, err := BuildUpdatePlan(origin.Components, target.Components)
	if err != nil {
		return nil, err
	}
	plan, err = applyUpdate(ctx, rt, updater, journal, plan, timeout)
	if err != nil {
		if rollbackErr := rollbackUpdate(ctx, rt, updater, journal, timeout); rollbackErr != nil {
			return plan, errors.Join(err, rollbackErr)
		}
		return plan, fmt.Errorf("update failed and changes were rolled back: %w", err)
	}
	if err := commitUpdate(ctx, rt, target, journal, rt.GetWorkdirPath(UpdateStateName), timeout); err != nil {
		return plan, err
	}
	return plan, nil
}

func parseStep(step string) (kind, name string, ok bool) {
	for _, prefix := range []string{stepStopComponent, stepRemoveComponent, stepApplyComponent} {
		if len(step) > len(prefix)+1 && step[:len(prefix)] == prefix && step[len(prefix)] == ':' {
			return prefix, step[len(prefix)+1:], true
		}
	}
	return "", "", false
}

// --- journal persistence ---

type updateJournalAction struct {
	Name   string                `json:"name"`
	Action ComponentChangeAction `json:"action"`
}

// updateJournal is the durable recovery state of a component update transaction.
type updateJournal struct {
	// Phase is applying, committing or rollingback.
	Phase string `json:"phase"`
	// Up records whether the cluster was running when the transaction started.
	Up bool `json:"up"`
	// StartedAt is the transaction creation time.
	StartedAt time.Time `json:"startedAt"`
	// Origin and Target are YAML-serialized KwokctlConfiguration documents.
	Origin string `json:"origin"`
	Target string `json:"target"`
	// Actions records the planned action per component.
	Actions []updateJournalAction `json:"actions"`
	// Done lists completed forward steps, in completion order.
	Done []string `json:"done"`
	// RolledBack lists completed rollback steps.
	RolledBack []string `json:"rolledBack"`
}

func newUpdateJournal(origin, target *internalversion.KwokctlConfiguration, plan *UpdatePlan, up bool) (*updateJournal, error) {
	originData, err := config.Marshal(origin)
	if err != nil {
		return nil, fmt.Errorf("failed to encode current configuration: %w", err)
	}
	targetData, err := config.Marshal(target)
	if err != nil {
		return nil, fmt.Errorf("failed to encode target configuration: %w", err)
	}

	actions := make([]updateJournalAction, 0, len(plan.Changes))
	for _, change := range plan.Changes {
		actions = append(actions, updateJournalAction{
			Name:   change.Name,
			Action: change.Action,
		})
	}

	return &updateJournal{
		Phase:     updatePhaseApplying,
		Up:        up,
		StartedAt: time.Now(),
		Origin:    string(originData),
		Target:    string(targetData),
		Actions:   actions,
	}, nil
}

func (j *updateJournal) origin() *internalversion.KwokctlConfiguration {
	conf, err := config.UnmarshalWithType[*internalversion.KwokctlConfiguration, string](j.Origin)
	if err != nil {
		// The journal was produced by this package and is only rewritten as a whole.
		panic(fmt.Sprintf("corrupted update journal origin: %v", err))
	}
	return conf
}

func (j *updateJournal) target() *internalversion.KwokctlConfiguration {
	conf, err := config.UnmarshalWithType[*internalversion.KwokctlConfiguration, string](j.Target)
	if err != nil {
		panic(fmt.Sprintf("corrupted update journal target: %v", err))
	}
	return conf
}

func (j *updateJournal) changes() []ComponentChange {
	changes := make([]ComponentChange, 0, len(j.Actions))
	for _, action := range j.Actions {
		changes = append(changes, ComponentChange{Name: action.Name, Action: action.Action})
	}
	return changes
}

func (j *updateJournal) save(path string) error {
	data, err := yaml.Marshal(j)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func loadUpdateJournal(path string) (*updateJournal, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	journal := &updateJournal{}
	if err := yaml.Unmarshal(data, journal); err != nil {
		return nil, false, err
	}
	if journal.Origin == "" || journal.Target == "" {
		return nil, false, fmt.Errorf("update state file %s is incomplete", path)
	}
	return journal, true, nil
}

// --- advisory locking ---

func acquireUpdateLock(rt Runtime) (*os.File, error) {
	path := rt.GetWorkdirPath(updateLockName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	lockFile, err := flock.OpenFile(path)
	if err != nil {
		return nil, err
	}
	if err := flock.TryLock(lockFile); err != nil {
		_ = lockFile.Close()
		if errors.Is(err, flock.ErrLocked) {
			return nil, fmt.Errorf("another component update is in progress for this cluster")
		}
		return nil, err
	}
	return lockFile, nil
}

func releaseUpdateLock(lockFile *os.File) error {
	return errors.Join(flock.Unlock(lockFile), lockFile.Close())
}
