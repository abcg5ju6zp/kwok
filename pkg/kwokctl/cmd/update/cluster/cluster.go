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

// Package cluster contains a command to update the components of a cluster.
package cluster

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"sigs.k8s.io/kwok/pkg/apis/internalversion"
	"sigs.k8s.io/kwok/pkg/config"
	"sigs.k8s.io/kwok/pkg/consts"
	"sigs.k8s.io/kwok/pkg/kwokctl/runtime"
	"sigs.k8s.io/kwok/pkg/log"
	"sigs.k8s.io/kwok/pkg/utils/completion"
	utilspath "sigs.k8s.io/kwok/pkg/utils/path"
)

type flagpole struct {
	Name    string
	Timeout time.Duration
	Wait    time.Duration

	Enable  []string
	Disable []string

	PrometheusPort  uint32
	JaegerPort      uint32
	KueuevizPort    uint32
	ControllerPort  uint32
	QuietPull       bool
	PrometheusImage string
	JaegerImage     string

	MetricsServerImage  string
	KwokControllerImage string

	PrometheusBinary    string
	JaegerBinary        string
	MetricsServerBinary string

	ExtraArgs []string
}

// NewCommand returns a new cobra.Command for updating cluster components.
func NewCommand(ctx context.Context) *cobra.Command {
	flags := &flagpole{
		Wait: 2 * time.Minute,
	}
	cmd := &cobra.Command{
		Args:              cobra.NoArgs,
		Use:               "cluster",
		Short:             "Updates the enabled components and component parameters of a cluster",
		Long:              "Updates the enabled components and component parameters of an existing cluster without deleting and recreating it. Unchanged components and Kubernetes resources are retained; the change set is validated first and applied transactionally with rollback and crash recovery.",
		ValidArgsFunction: completion.NoFileCompletions,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags.Name = config.DefaultCluster
			return runE(cmd.Context(), cmd, flags)
		},
	}

	cmd.Flags().StringSliceVar(&flags.Enable, "enable", nil, `New full list of components to enable`)
	_ = cmd.RegisterFlagCompletionFunc("enable", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		availableComponents := []string{
			consts.ComponentMetricsServer,
			consts.ComponentPrometheus,
			consts.ComponentJaeger,
			consts.ComponentKueue,
			consts.ComponentJobSet,
			consts.ComponentLWS,
			consts.ComponentSchedulerPlugins,
			consts.ComponentDescheduler,
			consts.ComponentNodeReadinessController,
		}
		return availableComponents, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.Flags().StringSliceVar(&flags.Disable, "disable", nil, `New full list of components to disable`)
	_ = cmd.RegisterFlagCompletionFunc("disable", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{
			consts.ComponentKubeControllerManager,
			consts.ComponentKubeScheduler,
		}, cobra.ShellCompDirectiveNoFileComp
	})

	cmd.Flags().Uint32Var(&flags.PrometheusPort, "prometheus-port", 0, `Port to expose Prometheus metrics (0 leaves it unchanged)`)
	cmd.Flags().Uint32Var(&flags.JaegerPort, "jaeger-port", 0, `Port to expose Jaeger UI (0 leaves it unchanged)`)
	cmd.Flags().Uint32Var(&flags.KueuevizPort, "kueueviz-port", 0, `Port of kueueviz exposed to the host (0 leaves it unchanged)`)
	cmd.Flags().Uint32Var(&flags.ControllerPort, "controller-port", 0, `Port of kwok-controller exposed to the host (0 leaves it unchanged)`)
	cmd.Flags().BoolVar(&flags.QuietPull, "quiet-pull", false, `Pull images without printing progress information`)
	cmd.Flags().StringVar(&flags.PrometheusImage, "prometheus-image", "", `Image of Prometheus`)
	cmd.Flags().StringVar(&flags.JaegerImage, "jaeger-image", "", `Image of Jaeger`)
	cmd.Flags().StringVar(&flags.MetricsServerImage, "metrics-server-image", "", `Image of metrics-server`)
	cmd.Flags().StringVar(&flags.KwokControllerImage, "kwok-controller-image", "", `Image of kwok-controller`)
	cmd.Flags().StringVar(&flags.PrometheusBinary, "prometheus-binary", "", `Binary of Prometheus, only for the binary runtime`)
	cmd.Flags().StringVar(&flags.JaegerBinary, "jaeger-binary", "", `Binary of Jaeger, only for the binary runtime`)
	cmd.Flags().StringVar(&flags.MetricsServerBinary, "metrics-server-binary", "", `Binary of metrics-server, only for the binary runtime`)
	cmd.Flags().StringArrayVar(&flags.ExtraArgs, "extra-args", nil, "Pass an extra arg key-value pair to a component in the format `component=key=value` (repeatable)")

	cmd.Flags().DurationVar(&flags.Timeout, "timeout", flags.Timeout, "Timeout for the whole update operation")
	cmd.Flags().DurationVar(&flags.Wait, "wait", flags.Wait, "Wait for each changed component to become ready")

	return cmd
}

func runE(ctx context.Context, cmd *cobra.Command, flags *flagpole) error {
	name := flags.Name
	workdir := utilspath.Join(config.ClustersDir, flags.Name)

	logger := log.FromContext(ctx)
	logger = logger.With(
		"cluster", flags.Name,
	)
	ctx = log.NewContext(ctx, logger)

	if flags.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, flags.Timeout)
		defer cancel()
	}

	rt, err := runtime.DefaultRegistry.Load(ctx, name, workdir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn("Cluster does not exist")
		}
		return err
	}

	origin, err := rt.Config(ctx)
	if err != nil {
		return err
	}
	target := origin.DeepCopy()
	options := &target.Options

	changed := func(flag string) bool { return cmd.Flags().Changed(flag) }

	if changed("enable") {
		options.Enable = flags.Enable
	}
	if changed("disable") {
		options.Disable = flags.Disable
	}
	if changed("prometheus-port") {
		options.PrometheusPort = flags.PrometheusPort
	}
	if changed("jaeger-port") {
		options.JaegerPort = flags.JaegerPort
	}
	if changed("kueueviz-port") {
		options.KueuevizPort = flags.KueuevizPort
	}
	if changed("controller-port") {
		options.KwokControllerPort = flags.ControllerPort
	}
	if changed("quiet-pull") {
		options.QuietPull = flags.QuietPull
	}
	if changed("prometheus-image") {
		options.PrometheusImage = flags.PrometheusImage
	}
	if changed("jaeger-image") {
		options.JaegerImage = flags.JaegerImage
	}
	if changed("metrics-server-image") {
		options.MetricsServerImage = flags.MetricsServerImage
	}
	if changed("kwok-controller-image") {
		options.KwokControllerImage = flags.KwokControllerImage
	}
	if changed("prometheus-binary") {
		options.PrometheusBinary = flags.PrometheusBinary
	}
	if changed("jaeger-binary") {
		options.JaegerBinary = flags.JaegerBinary
	}
	if changed("metrics-server-binary") {
		options.MetricsServerBinary = flags.MetricsServerBinary
	}

	if changed("extra-args") {
		patches := buildComponentPatches(flags.ExtraArgs)
		target.ComponentsPatches = mergeComponentPatches(target.ComponentsPatches, patches)
	}

	plan, err := runtime.UpdateClusterComponents(ctx, rt, runtime.UpdateComponentsOptions{
		Target:      target,
		WaitTimeout: flags.Wait,
	})
	if err != nil {
		return err
	}

	if rt.IsDryRun() {
		return nil
	}

	logger.Info("Cluster components updated",
		"stopped", plan.StopComponents(),
		"replaced", plan.ReplaceComponents(),
		"started", plan.StartComponents(),
	)
	return nil
}

// buildComponentPatches converts component=key=value flags into component patches.
func buildComponentPatches(extraArgs []string) []internalversion.ComponentPatches {
	var componentPatches []internalversion.ComponentPatches
	componentNames := map[string]int{}
	for _, extraArg := range extraArgs {
		splitArgs := strings.SplitN(extraArg, "=", 3)
		if len(splitArgs) != 3 {
			continue
		}
		if n, ok := componentNames[splitArgs[0]]; ok {
			componentPatches[n].ExtraArgs = append(componentPatches[n].ExtraArgs, internalversion.ExtraArgs{
				Key:   splitArgs[1],
				Value: new(splitArgs[2]),
			})
			continue
		}
		componentPatches = append(componentPatches, internalversion.ComponentPatches{
			Name: splitArgs[0],
			ExtraArgs: []internalversion.ExtraArgs{{
				Key:   splitArgs[1],
				Value: new(splitArgs[2]),
			}},
		})
		componentNames[splitArgs[0]] = len(componentPatches) - 1
	}
	return componentPatches
}

// mergeComponentPatches merges freshly supplied patches into the persisted
// patches; later entries override earlier ones for the same component.
func mergeComponentPatches(existing, fresh []internalversion.ComponentPatches) []internalversion.ComponentPatches {
	index := map[string]int{}
	merged := slices.Clone(existing)
	for i, patch := range merged {
		index[patch.Name] = i
	}
	for _, patch := range fresh {
		if i, ok := index[patch.Name]; ok {
			merged[i].ExtraArgs = append(merged[i].ExtraArgs, patch.ExtraArgs...)
			merged[i].ExtraVolumes = append(merged[i].ExtraVolumes, patch.ExtraVolumes...)
			merged[i].ExtraEnvs = append(merged[i].ExtraEnvs, patch.ExtraEnvs...)
			continue
		}
		index[patch.Name] = len(merged)
		merged = append(merged, patch)
	}
	return merged
}
