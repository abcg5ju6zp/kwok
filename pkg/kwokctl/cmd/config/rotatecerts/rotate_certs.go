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

// Package rotatecerts implements the config rotate-certs command
package rotatecerts

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/spf13/cobra"

	"sigs.k8s.io/kwok/pkg/config"
	"sigs.k8s.io/kwok/pkg/kwokctl/runtime"
	"sigs.k8s.io/kwok/pkg/log"
	"sigs.k8s.io/kwok/pkg/utils/completion"
	utilspath "sigs.k8s.io/kwok/pkg/utils/path"
)

type flagpole struct {
	Name    string
	Timeout time.Duration
}

// NewCommand returns a new cobra.Command for rotating cluster certificates
func NewCommand(ctx context.Context) *cobra.Command {
	flags := &flagpole{}
	cmd := &cobra.Command{
		Args:              cobra.NoArgs,
		Use:               "rotate-certs",
		Short:             "Rotate the CA and certificates of a cluster",
		ValidArgsFunction: completion.NoFileCompletions,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags.Name = config.DefaultCluster
			return runE(cmd.Context(), flags)
		},
	}

	cmd.Flags().DurationVar(&flags.Timeout, "timeout", 10*time.Minute, "Timeout for the certificate rotation")
	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	name := flags.Name
	workdir := utilspath.Join(config.ClustersDir, name)

	logger := log.FromContext(ctx)
	logger = logger.With(
		"cluster", name,
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

	start := time.Now()
	logger.Info("Certificate rotation is starting")
	err = rt.RotateCertificates(ctx)
	if err != nil {
		return err
	}
	logger.Info("Certificate rotation is finished",
		"elapsed", time.Since(start),
	)
	return nil
}
