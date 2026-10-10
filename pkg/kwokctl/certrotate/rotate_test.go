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
	"os"
	"path/filepath"
	"testing"
	"time"

	"sigs.k8s.io/kwok/pkg/kwokctl/pki"
)

var testEnabledComponents = []string{
	"etcd",
	"kube-apiserver",
	"kube-controller-manager",
	"kube-scheduler",
	"kwok-controller",
}

type fakeHooks struct {
	clusterName string
	pkiDir      string
	profile     Profile
	enabled     []string

	switchErrorOn string
	switchCalls   []string
	restartCalls  []string
	generations   []string

	verifyAccessCalls int

	// failFirstKubeconfigPublish makes the first kubeconfig publishing attempt
	// fail, simulating a crash/failure right before the rotation is committed.
	failFirstKubeconfigPublish bool
	publishKubeconfigAttempts  int
	publishClientsAttempts     int
}

func (f *fakeHooks) ClusterName() string { return f.clusterName }
func (f *fakeHooks) PkiDir() string      { return f.pkiDir }
func (f *fakeHooks) Profile() Profile    { return f.profile }

func (f *fakeHooks) ExtraSANs(context.Context) ([]string, error) {
	return []string{"extra-san.example"}, nil
}

func (f *fakeHooks) EnabledComponents(context.Context) ([]string, error) {
	return append([]string{}, f.enabled...), nil
}

func (f *fakeHooks) SwitchComponent(_ context.Context, name string, gen Generation) error {
	f.generations = append(f.generations, gen.ID)
	f.switchCalls = append(f.switchCalls, name)

	// kind profile: verify the dependency ordered material publication.
	if f.profile == ProfileKind {
		switch name {
		case "etcd":
			newEtcd, err := os.ReadFile(filepath.Join(gen.NewDir, "etcd", "server.crt"))
			if err != nil {
				return err
			}
			liveEtcd, err := os.ReadFile(filepath.Join(f.pkiDir, "etcd", "server.crt"))
			if err != nil {
				return err
			}
			if string(newEtcd) != string(liveEtcd) {
				return errors.New("etcd material was not published at the etcd stage")
			}
			newApiserver, err := os.ReadFile(filepath.Join(gen.NewDir, "apiserver.crt"))
			if err != nil {
				return err
			}
			liveApiserver, err := os.ReadFile(filepath.Join(f.pkiDir, "apiserver.crt"))
			if err != nil {
				return err
			}
			if string(newApiserver) == string(liveApiserver) {
				return errors.New("apiserver material must not be published before the etcd stage")
			}
		case "kube-apiserver":
			newApiserver, err := os.ReadFile(filepath.Join(gen.NewDir, "apiserver.crt"))
			if err != nil {
				return err
			}
			liveApiserver, err := os.ReadFile(filepath.Join(f.pkiDir, "apiserver.crt"))
			if err != nil {
				return err
			}
			if string(newApiserver) != string(liveApiserver) {
				return errors.New("apiserver material was not published at the apiserver stage")
			}
		}
	}

	if f.switchErrorOn == name {
		return errors.New("simulated component switch failure")
	}
	return nil
}

func (f *fakeHooks) RestartComponent(_ context.Context, name string) error {
	f.restartCalls = append(f.restartCalls, name)
	return nil
}

func (f *fakeHooks) RestoreComponent(context.Context, string, Generation) error {
	return nil
}

func (f *fakeHooks) VerifyAccess(context.Context) error {
	f.verifyAccessCalls++
	return nil
}

func (f *fakeHooks) publishClientFiles(_ context.Context, gen Generation) ([]string, error) {
	f.publishClientsAttempts++
	clientsPath := filepath.Join(f.pkiDir, "clients.kubeconfig")
	if err := BackupFiles(gen.ClientsBackupDir(), []string{clientsPath}); err != nil {
		return nil, err
	}
	return []string{clientsPath}, os.WriteFile(clientsPath, []byte("new-clients"), 0o644)
}

func (f *fakeHooks) PublishClients(ctx context.Context, gen Generation) error {
	_, err := f.publishClientFiles(ctx, gen)
	return err
}

func (f *fakeHooks) RestoreClients(_ context.Context, gen Generation) error {
	return RestoreFiles(gen.ClientsBackupDir())
}

func (f *fakeHooks) PublishKubeconfig(_ context.Context, gen Generation) error {
	f.publishKubeconfigAttempts++
	hostPath := filepath.Join(f.pkiDir, "kubeconfig.yaml")
	if err := BackupFiles(gen.KubeconfigBackupDir(), []string{hostPath}); err != nil {
		return err
	}
	if f.failFirstKubeconfigPublish && f.publishKubeconfigAttempts == 1 {
		return errors.New("simulated kubeconfig publish failure")
	}
	return os.WriteFile(hostPath, []byte("new-kubeconfig"), 0o644)
}

func (f *fakeHooks) RestoreKubeconfig(_ context.Context, gen Generation) error {
	return RestoreFiles(gen.KubeconfigBackupDir())
}

func newFakeHooks(t *testing.T, profile Profile) *fakeHooks {
	t.Helper()
	pkiDir := t.TempDir()
	if profile == ProfileKind {
		mustGenerateKindLivePki(t, pkiDir)
	} else {
		mustGenerateLivePki(t, pkiDir)
	}
	// Client files that the publishing stages are expected to keep working.
	if err := os.WriteFile(filepath.Join(pkiDir, "clients.kubeconfig"), []byte("old-clients"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkiDir, "kubeconfig.yaml"), []byte("old-kubeconfig"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &fakeHooks{
		clusterName: "kwok-test",
		pkiDir:      pkiDir,
		profile:     profile,
		enabled:     append([]string{}, testEnabledComponents...),
	}
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func rotationWorkspaceExists(t *testing.T, f *fakeHooks) bool {
	t.Helper()
	_, err := os.Stat(rotationRoot(f.pkiDir))
	return !os.IsNotExist(err)
}

func TestRotateCoreHappyPath(t *testing.T) {
	t.Parallel()
	f := newFakeHooks(t, ProfileCore)
	oldCA, err := os.ReadFile(filepath.Join(f.pkiDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	if err := Rotate(context.Background(), f); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	// etcd does not consume material in the core profile; switch order is
	// API server first, then the other components in dependency order.
	wantOrder := []string{
		"kube-apiserver",
		"kube-controller-manager",
		"kube-scheduler",
		"kwok-controller",
	}
	if len(f.switchCalls) != len(wantOrder) {
		t.Fatalf("unexpected switch order %v", f.switchCalls)
	}
	for i, name := range wantOrder {
		if f.switchCalls[i] != name {
			t.Fatalf("unexpected switch order %v, want %v", f.switchCalls, wantOrder)
		}
	}
	if f.verifyAccessCalls == 0 {
		t.Fatal("the new trust chain was never verified")
	}

	if rotationWorkspaceExists(t, f) {
		t.Fatal("rotation workspace was not removed after completion")
	}
	newCA, err := os.ReadFile(filepath.Join(f.pkiDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(newCA) == string(oldCA) {
		t.Fatal("live CA was not replaced by the target generation")
	}
	// The live credential must be signed by the live CA.
	liveCert := mustReadCert(t, filepath.Join(f.pkiDir, "admin.crt"))
	liveCA := mustReadCert(t, filepath.Join(f.pkiDir, "ca.crt"))
	if err := liveCert.CheckSignatureFrom(liveCA); err != nil {
		t.Fatalf("live admin cert is not signed by the live CA: %v", err)
	}

	if got := readFileString(t, filepath.Join(f.pkiDir, "clients.kubeconfig")); got != "new-clients" {
		t.Fatalf("clients kubeconfig not published, got %q", got)
	}
	if got := readFileString(t, filepath.Join(f.pkiDir, "kubeconfig.yaml")); got != "new-kubeconfig" {
		t.Fatalf("host kubeconfig not published, got %q", got)
	}
}

func TestRotateKindHappyPath(t *testing.T) {
	t.Parallel()
	f := newFakeHooks(t, ProfileKind)
	oldCA, err := os.ReadFile(filepath.Join(f.pkiDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	if err := Rotate(context.Background(), f); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	wantOrder := []string{
		"etcd",
		"kube-apiserver",
		"kube-controller-manager",
		"kube-scheduler",
		"kwok-controller",
	}
	if len(f.switchCalls) != len(wantOrder) {
		t.Fatalf("unexpected switch order %v", f.switchCalls)
	}
	for i, name := range wantOrder {
		if f.switchCalls[i] != name {
			t.Fatalf("unexpected switch order %v, want %v", f.switchCalls, wantOrder)
		}
	}
	if rotationWorkspaceExists(t, f) {
		t.Fatal("rotation workspace was not removed after completion")
	}
	newCA, err := os.ReadFile(filepath.Join(f.pkiDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(newCA) == string(oldCA) {
		t.Fatal("live CA was not replaced by the target generation")
	}
}

func TestRotateNoopWithoutCA(t *testing.T) {
	t.Parallel()
	f := newFakeHooks(t, ProfileCore)
	if err := os.Remove(filepath.Join(f.pkiDir, "ca.crt")); err != nil {
		t.Fatal(err)
	}
	if err := Rotate(context.Background(), f); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if len(f.switchCalls) != 0 {
		t.Fatalf("components were switched on a cluster without a CA: %v", f.switchCalls)
	}
	if rotationWorkspaceExists(t, f) {
		t.Fatal("no rotation workspace must be created for a cluster that needs no rotation")
	}
}

func TestPrepareFailureDoesNotTouchCluster(t *testing.T) {
	// Not parallel: this test swaps global generation/validation seams.
	f := newFakeHooks(t, ProfileCore)
	oldCA, err := os.ReadFile(filepath.Join(f.pkiDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	origValidate := validateMaterialFn
	validateMaterialFn = func(string, Profile, string, time.Time) error {
		return errors.New("simulated validation failure")
	}
	defer func() { validateMaterialFn = origValidate }()

	if err := Rotate(context.Background(), f); err == nil {
		t.Fatal("expected Rotate to fail")
	}
	newCA, err := os.ReadFile(filepath.Join(f.pkiDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(newCA) != string(oldCA) {
		t.Fatal("the live CA was modified despite preparation failing")
	}
	if len(f.switchCalls) != 0 {
		t.Fatalf("components were switched although preparation failed: %v", f.switchCalls)
	}
	if rotationWorkspaceExists(t, f) {
		t.Fatal("failed preparation must not leave a journal")
	}
	if got := readFileString(t, filepath.Join(f.pkiDir, "kubeconfig.yaml")); got != "old-kubeconfig" {
		t.Fatalf("kubeconfig was modified despite preparation failing: %q", got)
	}
}

func TestControllerSwitchFailureRollsBack(t *testing.T) {
	t.Parallel()
	f := newFakeHooks(t, ProfileCore)
	oldCA, err := os.ReadFile(filepath.Join(f.pkiDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	f.switchErrorOn = "kube-controller-manager"

	err = Rotate(context.Background(), f)
	if err == nil {
		t.Fatal("expected Rotate to fail")
	}

	// Failed component plus everything confirmed before it is restarted with
	// the restored previous generation, in reverse switch order.
	wantRestart := []string{"kube-controller-manager", "kube-apiserver"}
	if len(f.restartCalls) != len(wantRestart) {
		t.Fatalf("unexpected restart order %v", f.restartCalls)
	}
	for i, name := range wantRestart {
		if f.restartCalls[i] != name {
			t.Fatalf("unexpected restart order %v, want %v", f.restartCalls, wantRestart)
		}
	}

	restoredCA, err := os.ReadFile(filepath.Join(f.pkiDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredCA) != string(oldCA) {
		t.Fatal("the live CA was not restored to the previous generation")
	}
	if rotationWorkspaceExists(t, f) {
		t.Fatal("rollback must remove the rotation workspace")
	}
	if got := readFileString(t, filepath.Join(f.pkiDir, "kubeconfig.yaml")); got != "old-kubeconfig" {
		t.Fatalf("publishing artifacts changed during a rolled back rotation: %q", got)
	}
}

func TestKubeconfigPublishFailureIsResumableWithoutReswitchingComponents(t *testing.T) {
	// Not parallel: this test swaps the global validation seam.
	f := newFakeHooks(t, ProfileCore)
	f.failFirstKubeconfigPublish = true

	// First attempt: all components accept the new generation, the final
	// kubeconfig publish fails.
	if err := Rotate(context.Background(), f); err == nil {
		t.Fatal("expected Rotate to fail")
	}
	if !rotationWorkspaceExists(t, f) {
		t.Fatal("the journal must survive a publishing failure so the rotation can be resumed")
	}
	switchesAfterFirstAttempt := len(f.switchCalls)
	if switchesAfterFirstAttempt == 0 {
		t.Fatal("components were not switched before the publishing failure")
	}
	if got := readFileString(t, filepath.Join(f.pkiDir, "kubeconfig.yaml")); got != "old-kubeconfig" {
		t.Fatalf("kubeconfig should have been rolled back, got %q", got)
	}

	// Second request continues the same generation and only retries the
	// unfinished publishing step.
	if err := Rotate(context.Background(), f); err != nil {
		t.Fatalf("resumed Rotate failed: %v", err)
	}
	if len(f.switchCalls) != switchesAfterFirstAttempt {
		t.Fatalf("components were switched again on resume: before=%d after=%d", switchesAfterFirstAttempt, len(f.switchCalls))
	}
	if f.publishKubeconfigAttempts != 2 {
		t.Fatalf("kubeconfig publish should have been retried, attempts=%d", f.publishKubeconfigAttempts)
	}
	if got := readFileString(t, filepath.Join(f.pkiDir, "kubeconfig.yaml")); got != "new-kubeconfig" {
		t.Fatalf("kubeconfig not published after resume, got %q", got)
	}
	if rotationWorkspaceExists(t, f) {
		t.Fatal("rotation workspace was not removed after completion")
	}
}

func TestResumeFromPreparedJournalKeepsGeneration(t *testing.T) {
	t.Parallel()
	f := newFakeHooks(t, ProfileCore)

	// Simulate a process that died after the isolated generation was prepared
	// and journaled, but before any component was switched.
	state, err := newState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	gen := generationOf(f.pkiDir, state.Generation)
	if err := saveState(f.pkiDir, state); err != nil {
		t.Fatal(err)
	}
	if err := prepareGeneration(context.Background(), f, gen, state); err != nil {
		t.Fatal(err)
	}
	state.Phase = PhasePrepared
	if err := saveState(f.pkiDir, state); err != nil {
		t.Fatal(err)
	}

	// The resumed rotation must not generate material again.
	origGenerate := generateMaterialFn
	generateMaterialFn = func(context.Context, string, Profile, string, []string, string) error {
		t.Fatal("material generation must not run again when resuming a prepared generation")
		return nil
	}
	defer func() { generateMaterialFn = origGenerate }()

	if err := Rotate(context.Background(), f); err != nil {
		t.Fatalf("resumed Rotate failed: %v", err)
	}
	for _, id := range f.generations {
		if id != state.Generation {
			t.Fatalf("resume started a different generation %q, want %q", id, state.Generation)
		}
	}
}

func TestResumeFailsWhenWorkspaceIsLost(t *testing.T) {
	t.Parallel()
	f := newFakeHooks(t, ProfileCore)

	state, err := newState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Journal claims that etcd was already switched, but the isolated
	// directory (and the rollback material) is gone.
	state.Phase = PhaseEtcdSwitched
	state.SwitchedComponents = []string{"etcd"}
	if err := saveState(f.pkiDir, state); err != nil {
		t.Fatal(err)
	}

	if err := Rotate(context.Background(), f); err == nil {
		t.Fatal("expected Rotate to refuse resuming without rollback material")
	}
	if len(f.switchCalls) != 0 {
		t.Fatalf("components must not be switched when the workspace is inconsistent: %v", f.switchCalls)
	}
}

func TestRepeatedRequestContinuesSameGenerationAfterCrash(t *testing.T) {
	t.Parallel()
	f := newFakeHooks(t, ProfileCore)

	// A process that crashes in the middle of preparing leaves the journal in
	// the Preparing phase. Repeating the request must continue that exact
	// generation, not start another one.
	state, err := newState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := saveState(f.pkiDir, state); err != nil {
		t.Fatal(err)
	}
	// Deliberately leave the workspace half initialized.
	if err := os.MkdirAll(generationOf(f.pkiDir, state.Generation).NewDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Rotate(context.Background(), f); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if len(f.generations) == 0 {
		t.Fatal("no components switched")
	}
	for _, id := range f.generations {
		if id != state.Generation {
			t.Fatalf("repeat request started a different generation %q, want %q", id, state.Generation)
		}
	}
}

func TestBackupRestoreFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	source := filepath.Join(dir, "a.conf")
	missing := filepath.Join(dir, "b.conf")
	if err := os.WriteFile(source, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup")
	if err := BackupFiles(backup, []string{source, missing}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RestoreFiles(backup); err != nil {
		t.Fatal(err)
	}
	if got := readFileString(t, source); got != "old" {
		t.Fatalf("restore returned %q, want old", got)
	}
}

// keep the pki import used even if helpers change
var _ = pki.DefaultCN
