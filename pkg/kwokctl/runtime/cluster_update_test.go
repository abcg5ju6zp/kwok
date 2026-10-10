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
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"sigs.k8s.io/kwok/pkg/apis/internalversion"
	"sigs.k8s.io/kwok/pkg/utils/client"
)

func comp(name string, links ...string) internalversion.Component {
	return internalversion.Component{
		Name:   name,
		Links:  links,
		Binary: "/usr/bin/" + name,
	}
}

func TestBuildUpdatePlanClassifiesActions(t *testing.T) {
	old := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
		comp("kwok-controller", "kube-apiserver"),
	}
	new := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
		comp("kwok-controller", "kube-apiserver"),
		comp("prometheus", "etcd", "kube-apiserver", "kwok-controller"),
	}

	plan, err := BuildUpdatePlan(old, new)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := plan.StartComponents(); len(got) != 1 || got[0] != "prometheus" {
		t.Fatalf("expected prometheus to be started, got %v", got)
	}
	if len(plan.StopComponents()) != 0 || len(plan.ReplaceComponents()) != 0 {
		t.Fatalf("expected no stop/replace changes, got stop=%v replace=%v", plan.StopComponents(), plan.ReplaceComponents())
	}
}

func TestBuildUpdatePlanStopAndReplace(t *testing.T) {
	old := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
		comp("kwok-controller", "kube-apiserver"),
		comp("prometheus", "etcd", "kube-apiserver", "kwok-controller"),
	}

	// prometheus changes its args; kwok-controller is removed.
	target := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
	}
	// Replace case: same components, but prometheus gets new args.
	replaceTarget := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
		comp("kwok-controller", "kube-apiserver"),
		func() internalversion.Component {
			c := comp("prometheus", "etcd", "kube-apiserver", "kwok-controller")
			c.Args = []string{"--new-arg=true"}
			return c
		}(),
	}

	planStop, err := BuildUpdatePlan(old, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := planStop.StopComponents(); len(got) != 2 {
		t.Fatalf("expected 2 stops, got %v", got)
	}
	// kwok-controller is a dependency of prometheus? in the stop target prometheus
	// is also removed; kwok-controller must be stopped after its dependents are gone.
	if got := planStop.StopComponents(); got[0] != "prometheus" || got[1] != "kwok-controller" {
		t.Fatalf("expected reverse dependency stop order [prometheus kwok-controller], got %v", got)
	}

	planReplace, err := BuildUpdatePlan(old, replaceTarget)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := planReplace.ReplaceComponents(); len(got) != 1 || got[0] != "prometheus" {
		t.Fatalf("expected prometheus to be replaced, got %v", got)
	}
}

func TestBuildUpdatePlanRejectsBrokenLinks(t *testing.T) {
	old := []internalversion.Component{comp("etcd")}
	new := []internalversion.Component{
		comp("etcd"),
		comp("prometheus", "etcd", "missing-dep"),
	}
	if _, err := BuildUpdatePlan(old, new); err == nil {
		t.Fatal("expected broken links error, got nil")
	}
}

func TestBuildUpdatePlanNoChanges(t *testing.T) {
	old := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
	}
	plan, err := BuildUpdatePlan(old, old)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Changes) != 0 {
		t.Fatalf("expected no changes, got %v", plan.Changes)
	}
}

func TestParseStep(t *testing.T) {
	cases := []struct {
		step     string
		wantKind string
		wantName string
		wantOK   bool
	}{
		{"stop:etcd", stepStopComponent, "etcd", true},
		{"remove:prometheus", stepRemoveComponent, "prometheus", true},
		{"apply:jaeger", stepApplyComponent, "jaeger", true},
		{"crs", "", "", false},
		{"bogus", "", "", false},
	}
	for _, tc := range cases {
		kind, name, ok := parseStep(tc.step)
		if ok != tc.wantOK || kind != tc.wantKind || name != tc.wantName {
			t.Fatalf("parseStep(%q) = %q,%q,%v; want %q,%q,%v", tc.step, kind, name, ok, tc.wantKind, tc.wantName, tc.wantOK)
		}
	}
}

func TestUpdateJournalRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, UpdateStateName)

	origin := &internalversion.KwokctlConfiguration{Components: []internalversion.Component{comp("etcd")}}
	origin.Name = "origin"
	target := &internalversion.KwokctlConfiguration{Components: []internalversion.Component{comp("etcd"), comp("prometheus", "etcd")}}
	target.Name = "target"

	plan, err := BuildUpdatePlan(origin.Components, target.Components)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	journal, err := newUpdateJournal(origin, target, plan, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := journal.save(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	loaded, ok, err := loadUpdateJournal(path)
	if err != nil || !ok {
		t.Fatalf("expected journal to load, ok=%v err=%v", ok, err)
	}
	if loaded.Phase != updatePhaseApplying || !loaded.Up {
		t.Fatalf("unexpected journal header: %+v", loaded)
	}
	if got := loaded.origin().Components; len(got) != 1 || got[0].Name != "etcd" {
		t.Fatalf("unexpected origin components: %+v", got)
	}
	if got := loaded.target().Components; len(got) != 2 {
		t.Fatalf("unexpected target components: %+v", got)
	}
	if len(loaded.Actions) != 1 || loaded.Actions[0].Name != "prometheus" {
		t.Fatalf("unexpected actions: %+v", loaded.Actions)
	}

	if _, ok, err := loadUpdateJournal(filepath.Join(dir, "missing.yaml")); err != nil || ok {
		t.Fatalf("expected missing journal to report absent, ok=%v err=%v", ok, err)
	}
}

// --- full transaction tests with a fake runtime ---

type fakeUpdateRuntime struct {
	workdir string
	conf    *internalversion.KwokctlConfiguration

	// specs holds the currently effective component specifications.
	specs map[string]internalversion.Component
	// running is the set of running component names.
	running map[string]bool
	calls   []string

	// failApply makes ApplyComponent fail for the named components.
	failApply map[string]bool

	// renders is the component list produced per configuration name when
	// RenderComponents is called.
	renders map[string][]internalversion.Component

	saveFails bool
}

func newFakeUpdateRuntime(t *testing.T, components []internalversion.Component) *fakeUpdateRuntime {
	t.Helper()
	conf := &internalversion.KwokctlConfiguration{Components: components}
	specs := map[string]internalversion.Component{}
	running := map[string]bool{}
	for _, component := range components {
		specs[component.Name] = component
		running[component.Name] = true
	}
	return &fakeUpdateRuntime{
		workdir:   t.TempDir(),
		conf:      conf,
		specs:     specs,
		running:   running,
		failApply: map[string]bool{},
		renders:   map[string][]internalversion.Component{},
	}
}

func (f *fakeUpdateRuntime) record(call string) {
	f.calls = append(f.calls, call)
}

func (f *fakeUpdateRuntime) RenderComponents(_ context.Context, conf *internalversion.KwokctlConfiguration) (*internalversion.KwokctlConfiguration, error) {
	f.record("render")
	rendered := conf.DeepCopy()
	if components, ok := f.renders[conf.Name]; ok {
		rendered.Components = components
	}
	f.conf = rendered
	return rendered, nil
}

func (f *fakeUpdateRuntime) ApplyComponent(_ context.Context, name string, up bool, _ time.Duration) error {
	f.record("apply:" + name)
	component, err := f.GetComponent(context.Background(), name)
	if err != nil {
		return err
	}
	if f.failApply[name] && slices.Contains(component.Args, "--new=true") {
		return os.ErrPermission
	}
	f.specs[name] = component
	if up {
		f.running[name] = true
	}
	return nil
}

func (f *fakeUpdateRuntime) RemoveComponent(_ context.Context, name string, _ bool) error {
	f.record("remove:" + name)
	delete(f.specs, name)
	delete(f.running, name)
	return nil
}

func (f *fakeUpdateRuntime) SetConfig(_ context.Context, conf *internalversion.KwokctlConfiguration) error {
	f.conf = conf.DeepCopy()
	return nil
}

func (f *fakeUpdateRuntime) Config(_ context.Context) (*internalversion.KwokctlConfiguration, error) {
	return f.conf, nil
}

func (f *fakeUpdateRuntime) Save(_ context.Context) error {
	f.record("save")
	if f.saveFails {
		return os.ErrPermission
	}
	return nil
}

func (f *fakeUpdateRuntime) StopComponent(_ context.Context, name string) error {
	f.record("stop:" + name)
	f.running[name] = false
	return nil
}

func (f *fakeUpdateRuntime) StartComponent(_ context.Context, name string) error {
	f.record("start:" + name)
	f.running[name] = true
	return nil
}

func (f *fakeUpdateRuntime) GetComponent(_ context.Context, name string) (internalversion.Component, error) {
	for _, component := range f.conf.Components {
		if component.Name == name {
			return component, nil
		}
	}
	return internalversion.Component{}, ErrComponentNotFound
}

func (f *fakeUpdateRuntime) ListComponents(_ context.Context) ([]internalversion.Component, error) {
	return f.conf.Components, nil
}

func (f *fakeUpdateRuntime) InspectComponent(_ context.Context, name string) (ComponentStatus, error) {
	if !f.running[name] {
		return ComponentStatusStopped, nil
	}
	return ComponentStatusReady, nil
}

func (f *fakeUpdateRuntime) InitCRs(_ context.Context) error {
	f.record("crs")
	return nil
}

func (f *fakeUpdateRuntime) IsDryRun() bool { return false }

func (f *fakeUpdateRuntime) GetWorkdirPath(name string) string {
	return filepath.Join(f.workdir, name)
}

// The remaining Runtime methods are unused by the update transaction.

func (f *fakeUpdateRuntime) Available(context.Context) error { return nil }
func (f *fakeUpdateRuntime) Install(context.Context) error   { return nil }
func (f *fakeUpdateRuntime) Uninstall(context.Context) error { return nil }
func (f *fakeUpdateRuntime) Up(context.Context) error        { return nil }
func (f *fakeUpdateRuntime) Down(context.Context) error      { return nil }
func (f *fakeUpdateRuntime) Start(context.Context) error     { return nil }
func (f *fakeUpdateRuntime) Stop(context.Context) error      { return nil }
func (f *fakeUpdateRuntime) PortForward(context.Context, string, string, uint32) (func(), error) {
	return func() {}, nil
}
func (f *fakeUpdateRuntime) Ready(context.Context) (bool, error) { return true, nil }
func (f *fakeUpdateRuntime) WaitReady(context.Context, time.Duration) error {
	return nil
}
func (f *fakeUpdateRuntime) AddContext(context.Context, string) error    { return nil }
func (f *fakeUpdateRuntime) RemoveContext(context.Context, string) error { return nil }
func (f *fakeUpdateRuntime) Kubectl(context.Context, ...string) error    { return nil }
func (f *fakeUpdateRuntime) KubectlInCluster(context.Context, ...string) error {
	return nil
}
func (f *fakeUpdateRuntime) EtcdctlInCluster(context.Context, ...string) error { return nil }
func (f *fakeUpdateRuntime) Logs(context.Context, string, io.Writer) error     { return nil }
func (f *fakeUpdateRuntime) LogsFollow(context.Context, string, io.Writer) error {
	return nil
}
func (f *fakeUpdateRuntime) CollectLogs(context.Context, string) error { return nil }
func (f *fakeUpdateRuntime) AuditLogs(context.Context, io.Writer) error {
	return nil
}
func (f *fakeUpdateRuntime) AuditLogsFollow(context.Context, io.Writer) error {
	return nil
}
func (f *fakeUpdateRuntime) ListBinaries(context.Context) ([]string, error) { return nil, nil }
func (f *fakeUpdateRuntime) ListImages(context.Context) ([]string, error)   { return nil, nil }
func (f *fakeUpdateRuntime) SnapshotSave(context.Context, string) error     { return nil }
func (f *fakeUpdateRuntime) SnapshotRestore(context.Context, string) error  { return nil }
func (f *fakeUpdateRuntime) SnapshotSaveWithYAML(context.Context, string, SnapshotSaveWithYAMLConfig) error {
	return nil
}
func (f *fakeUpdateRuntime) SnapshotRestoreWithYAML(context.Context, string, SnapshotRestoreWithYAMLConfig) error {
	return nil
}
func (f *fakeUpdateRuntime) InitCRDs(context.Context) error { return nil }
func (f *fakeUpdateRuntime) GetClientset(context.Context) (client.Clientset, error) {
	return nil, nil
}
func (f *fakeUpdateRuntime) Kectl(context.Context, ...string) error { return nil }
func (f *fakeUpdateRuntime) KectlInCluster(context.Context, ...string) error {
	return nil
}

var _ Runtime = &fakeUpdateRuntime{}
var _ ComponentUpdater = &fakeUpdateRuntime{}

func callIndex(calls []string, want string) int {
	for i, call := range calls {
		if call == want {
			return i
		}
	}
	return -1
}

func TestApplyUpdateForwardSucceeds(t *testing.T) {
	old := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
		comp("kwok-controller", "kube-apiserver"),
	}
	fake := newFakeUpdateRuntime(t, old)

	targetComponents := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
		comp("kwok-controller", "kube-apiserver"),
		comp("prometheus", "etcd", "kube-apiserver", "kwok-controller"),
	}
	targetConf := &internalversion.KwokctlConfiguration{Components: targetComponents}
	targetConf.Name = "target"
	fake.renders["target"] = targetComponents

	plan, err := UpdateClusterComponents(context.Background(), fake, UpdateComponentsOptions{Target: targetConf})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.StartComponents()) != 1 {
		t.Fatalf("expected one start, got %v", plan.StartComponents())
	}
	if !fake.running["prometheus"] {
		t.Fatal("prometheus should be running")
	}
	if _, ok := fake.specs["prometheus"]; !ok {
		t.Fatal("prometheus spec should be installed")
	}
	if _, err := os.Stat(fake.GetWorkdirPath(UpdateStateName)); !os.IsNotExist(err) {
		t.Fatalf("update state should be cleared, stat err=%v", err)
	}
	if callIndex(fake.calls, "save") < 0 {
		t.Fatal("configuration should be saved")
	}
}

func TestApplyUpdateRollbackOnFailure(t *testing.T) {
	old := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
		comp("kwok-controller", "kube-apiserver"),
		comp("prometheus", "etcd", "kube-apiserver", "kwok-controller"),
	}
	fake := newFakeUpdateRuntime(t, old)
	fake.conf.Name = "origin"
	// Replacing prometheus fails; the transaction must roll back to the old spec.
	prom := comp("prometheus", "etcd", "kube-apiserver", "kwok-controller")
	prom.Args = []string{"--new=true"}
	targetComponents := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
		comp("kwok-controller", "kube-apiserver"),
		prom,
	}
	targetConf := &internalversion.KwokctlConfiguration{Components: targetComponents}
	targetConf.Name = "target"
	fake.renders["target"] = targetComponents
	fake.renders["origin"] = old
	fake.failApply["prometheus"] = true

	_, err := UpdateClusterComponents(context.Background(), fake, UpdateComponentsOptions{Target: targetConf})
	if err == nil {
		t.Fatal("expected update error, got nil")
	}

	// The committed (origin) specification is restored and running.
	if !fake.running["prometheus"] {
		t.Fatal("prometheus should be running again after rollback")
	}
	if got := fake.specs["prometheus"]; len(got.Args) != 0 {
		t.Fatalf("old spec should be restored, got args %v", got.Args)
	}
	if _, err := os.Stat(fake.GetWorkdirPath(UpdateStateName)); !os.IsNotExist(err) {
		t.Fatalf("update state should be cleared after rollback, stat err=%v", err)
	}
	if callIndex(fake.calls, "save") >= 0 {
		t.Fatal("configuration must not be saved on a rolled-back update")
	}
}

func TestResumeInterruptedUpdate(t *testing.T) {
	old := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
	}
	fake := newFakeUpdateRuntime(t, old)
	targetConf := &internalversion.KwokctlConfiguration{Components: []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
		comp("kwok-controller", "kube-apiserver"),
	}}

	// Simulate a process that crashed after the stop/start sweep recorded the
	// first steps but before commit.
	plan, err := BuildUpdatePlan(old, targetConf.Components)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	origin := (&internalversion.KwokctlConfiguration{Components: old})
	journal, err := newUpdateJournal(origin, targetConf, plan, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	journal.Done = []string{"apply:kwok-controller"}
	journalPath := fake.GetWorkdirPath(UpdateStateName)
	if err := journal.save(journalPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Pretend the component was already brought up by the dead process.
	fake.running["kwok-controller"] = true
	fake.specs["kwok-controller"] = comp("kwok-controller", "kube-apiserver")

	// A new invocation must resume the same transaction instead of restarting.
	plan, err = UpdateClusterComponents(context.Background(), fake, UpdateComponentsOptions{Target: targetConf})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fake.running["kwok-controller"] {
		t.Fatal("kwok-controller should be running after resume")
	}
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("update state should be cleared, stat err=%v", err)
	}
}

func TestNoChangeIsNoOp(t *testing.T) {
	old := []internalversion.Component{
		comp("etcd"),
		comp("kube-apiserver", "etcd"),
	}
	fake := newFakeUpdateRuntime(t, old)
	targetConf := &internalversion.KwokctlConfiguration{Components: old}
	targetConf.Name = "target"
	fake.renders["target"] = old

	plan, err := UpdateClusterComponents(context.Background(), fake, UpdateComponentsOptions{Target: targetConf})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Changes) != 0 {
		t.Fatalf("expected no changes, got %v", plan.Changes)
	}
	for _, call := range fake.calls {
		if call == "save" {
			t.Fatal("configuration should not be saved when nothing changed")
		}
	}
}
