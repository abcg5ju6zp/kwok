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
	"io"
	"testing"

	"sigs.k8s.io/kwok/pkg/apis/internalversion"
	"sigs.k8s.io/kwok/pkg/consts"
	"sigs.k8s.io/kwok/pkg/kwokctl/dryrun"
	"sigs.k8s.io/kwok/pkg/kwokctl/runtime"
	"sigs.k8s.io/kwok/pkg/log"
)

// TestRenderComponentsIsDeterministic ensures rendering the same options twice
// yields identical component specs, so updating an unchanged cluster plans no
// spurious replacements.
func TestRenderComponentsIsDeterministic(t *testing.T) {
	dryrun.DryRun = true
	t.Cleanup(func() {
		dryrun.DryRun = false
	})

	ctx := log.NewContext(context.Background(), log.NewLogger(io.Discard, log.LevelInfo))

	rt0, err := NewCluster("deterministic", t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rt := rt0.(*Cluster)

	options := internalversion.KwokctlConfigurationOptions{
		Runtime:                     consts.RuntimeTypeBinary,
		Components:                  []string{consts.ComponentEtcd, consts.ComponentKubeApiserver, consts.ComponentKubeControllerManager, consts.ComponentKubeScheduler, consts.ComponentKwokController},
		Enable:                      []string{consts.ComponentPrometheus, consts.ComponentJaeger},
		PrometheusPort:              9100,
		JaegerPort:                  9101,
		JaegerOtlpGrpcPort:          9102,
		KubeApiserverPort:           9103,
		EtcdPort:                    9104,
		EtcdPeerPort:                9105,
		KwokControllerPort:          9106,
		KubeControllerManagerPort:   9107,
		KubeSchedulerPort:           9108,
		BindAddress:                 "127.0.0.1",
		CacheDir:                    t.TempDir(),
		EtcdQuotaBackendSize:        "8Gi",
		EtcdBinary:                  "https://example.invalid/etcd",
		KubeApiserverBinary:         "https://example.invalid/kube-apiserver",
		KubeSchedulerBinary:         "https://example.invalid/kube-scheduler",
		KwokControllerBinary:        "https://example.invalid/kwok-controller",
		PrometheusBinary:            "https://example.invalid/prometheus",
		JaegerBinary:                "https://example.invalid/jaeger",
		MetricsServerBinary:         "https://example.invalid/metrics-server",
		KubeControllerManagerBinary: "https://example.invalid/kube-controller-manager",
	}

	first, err := rt.RenderComponents(ctx, &internalversion.KwokctlConfiguration{Options: options})
	if err != nil {
		t.Fatalf("first render failed: %v", err)
	}

	second, err := rt.RenderComponents(ctx, &internalversion.KwokctlConfiguration{Options: options})
	if err != nil {
		t.Fatalf("second render failed: %v", err)
	}

	plan, err := runtime.BuildUpdatePlan(first.Components, second.Components)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Changes) != 0 {
		t.Fatalf("expected no changes between identical renders, got %v", plan.Changes)
	}
}
