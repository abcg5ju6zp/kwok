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
	"testing"

	"sigs.k8s.io/kwok/pkg/apis/internalversion"
	"sigs.k8s.io/kwok/pkg/consts"
	"sigs.k8s.io/kwok/pkg/kwokctl/runtime"
)

func TestValidateKindUpdate(t *testing.T) {
	old := []internalversion.Component{
		{Name: consts.ComponentEtcd},
		{Name: consts.ComponentKubeApiserver, Links: []string{consts.ComponentEtcd}},
		{Name: consts.ComponentKubeScheduler, Links: []string{consts.ComponentKubeApiserver}},
		{Name: consts.ComponentPrometheus, Links: []string{consts.ComponentKubeApiserver}},
	}
	target := []internalversion.Component{
		{Name: consts.ComponentEtcd},
		func() internalversion.Component {
			c := old[1]
			c.Args = []string{"--new=true"}
			return c
		}(),
		old[2],
		func() internalversion.Component {
			c := old[3]
			c.Args = []string{"--new=true"}
			return c
		}(),
	}

	plan, err := runtime.BuildUpdatePlan(old, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := validateKindUpdate(plan); err == nil {
		t.Fatal("expected rejection of kube-apiserver parameter replacement on kind")
	}

	// Enabling/disabling core components and replacing file-managed addons is fine.
	old2 := []internalversion.Component{
		{Name: consts.ComponentEtcd},
		{Name: consts.ComponentKubeApiserver, Links: []string{consts.ComponentEtcd}},
	}
	target2 := []internalversion.Component{
		{Name: consts.ComponentEtcd},
		{Name: consts.ComponentKubeApiserver, Links: []string{consts.ComponentEtcd}},
		{Name: consts.ComponentKubeScheduler, Links: []string{consts.ComponentKubeApiserver}},
	}
	plan2, err := runtime.BuildUpdatePlan(old2, target2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateKindUpdate(plan2); err != nil {
		t.Fatalf("enabling kube-scheduler should be allowed: %v", err)
	}
}
