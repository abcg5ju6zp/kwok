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

package snapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
	testingclock "k8s.io/utils/clock/testing"

	"sigs.k8s.io/kwok/pkg/apis/action/v1alpha1"
	"sigs.k8s.io/kwok/pkg/kwokctl/recording"
	"sigs.k8s.io/kwok/pkg/log"
	utilsyaml "sigs.k8s.io/kwok/pkg/utils/yaml"
)

var (
	testGV       = schema.GroupVersion{Version: "v1"}
	testPodGVK   = testGV.WithKind("Pod")
	testPodGVR   = testGV.WithResource("pods")
	testCMGVK    = testGV.WithKind("ConfigMap")
	testCMGVR    = testGV.WithResource("configmaps")
	testBaseTime = time.Unix(1_700_000_000, 0)
)

type fakePatchLookups map[schema.GroupVersionResource]strategicpatch.LookupPatchMeta

func (f fakePatchLookups) Lookup(gvr schema.GroupVersionResource) (strategicpatch.LookupPatchMeta, error) {
	if lookup, ok := f[gvr]; ok {
		return lookup, nil
	}
	return nil, fmt.Errorf("patch metadata for %s is not available", gvr)
}

type scriptedWatcher struct {
	ch      chan watch.Event
	stopped atomic.Bool
}

func newScriptedWatcher() *scriptedWatcher {
	return &scriptedWatcher{ch: make(chan watch.Event, 32)}
}

func (w *scriptedWatcher) ResultChan() <-chan watch.Event { return w.ch }
func (w *scriptedWatcher) Stop()                          { w.stopped.Store(true) }
func (w *scriptedWatcher) send(event watch.Event)         { w.ch <- event }
func (w *scriptedWatcher) closeWatch()                    { close(w.ch) }

func expiredStatus() watch.Event {
	return watch.Event{
		Type: watch.Error,
		Object: &metav1.Status{
			Status:  metav1.StatusFailure,
			Code:    httpStatusGone,
			Reason:  metav1.StatusReasonExpired,
			Message: "too old resource version",
		},
	}
}

const httpStatusGone = 410

type recorderHarness struct {
	t          *testing.T
	dyn        *dynamicfake.FakeDynamicClient
	clk        *testingclock.FakePassiveClock
	saver      *Saver
	mu         sync.Mutex
	watchRV    map[string][]string
	scripted   map[string][]*scriptedWatcher
	listRV     []string
	listResult *unstructured.UnstructuredList
	podMap     *meta.RESTMapping
	cmMap      *meta.RESTMapping
}

func newRecorderHarness(t *testing.T) *recorderHarness {
	t.Helper()

	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		testPodGVR: "PodList",
		testCMGVR:  "ConfigMapList",
	})

	podMapping := &meta.RESTMapping{
		Resource:         testPodGVR,
		GroupVersionKind: testPodGVK,
		Scope:            meta.RESTScopeNamespace,
	}
	cmMapping := &meta.RESTMapping{
		Resource:         testCMGVR,
		GroupVersionKind: testCMGVK,
		Scope:            meta.RESTScopeNamespace,
	}

	podPatchMeta, err := strategicpatch.NewPatchMetaFromStruct(&corev1.Pod{})
	if err != nil {
		t.Fatalf("pod patch meta: %v", err)
	}
	cmPatchMeta, err := strategicpatch.NewPatchMetaFromStruct(&corev1.ConfigMap{})
	if err != nil {
		t.Fatalf("configmap patch meta: %v", err)
	}

	h := &recorderHarness{
		t:        t,
		dyn:      dyn,
		clk:      testingclock.NewFakePassiveClock(testBaseTime),
		watchRV:  map[string][]string{},
		scripted: map[string][]*scriptedWatcher{},
		podMap:   podMapping,
		cmMap:    cmMapping,
	}
	h.saver = &Saver{
		dynamicClient:   dyn,
		patchMetaSchema: fakePatchLookups{testPodGVR: podPatchMeta, testCMGVR: cmPatchMeta},
		clock:           h.clk,
		saveConfig: SaveConfig{
			PagerConfig: &PagerConfig{PageSize: 500, PageBufferSize: 1},
		},
	}

	dyn.PrependWatchReactor("*", func(action clienttesting.Action) (bool, watch.Interface, error) {
		watchAction := action.(clienttesting.WatchAction)
		resource := action.GetResource().Resource
		h.mu.Lock()
		defer h.mu.Unlock()
		h.watchRV[resource] = append(h.watchRV[resource], watchAction.GetWatchRestrictions().ResourceVersion)
		if len(h.scripted[resource]) == 0 {
			return true, newScriptedWatcher(), nil
		}
		watcher := h.scripted[resource][0]
		h.scripted[resource] = h.scripted[resource][1:]
		return true, watcher, nil
	})
	dyn.PrependReactor("list", "*", func(action clienttesting.Action) (bool, runtime.Object, error) {
		listAction := action.(clienttesting.ListAction)
		_ = listAction
		h.mu.Lock()
		h.listRV = append(h.listRV, action.GetResource().Resource)
		result := h.listResult
		h.mu.Unlock()
		return true, result, nil
	})

	return h
}

func (h *recorderHarness) queueWatchers(resource string, watchers ...*scriptedWatcher) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scripted[resource] = append(h.scripted[resource], watchers...)
}

func (h *recorderHarness) setListResult(objects ...runtime.Object) {
	list := &unstructured.UnstructuredList{}
	list.SetResourceVersion("20")
	list.Items = make([]unstructured.Unstructured, 0, len(objects))
	for _, object := range objects {
		if u, ok := object.(*unstructured.Unstructured); ok {
			list.Items = append(list.Items, *u)
		}
	}
	h.listResult = list
}

func (h *recorderHarness) run(ctx context.Context, tracks map[*meta.RESTMapping]*TrackData) (*bytes.Buffer, context.CancelFunc, chan error) {
	buf := &bytes.Buffer{}
	encoder := utilsyaml.NewEncoder(buf)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- h.saver.RecordWithConfig(runCtx, RecordConfig{
			Encoder:   encoder,
			Tracks:    tracks,
			StartTime: testBaseTime,
		})
	}()
	return buf, cancel, done
}

func mustTracks(mappings ...*meta.RESTMapping) map[*meta.RESTMapping]*TrackData {
	tracks := make(map[*meta.RESTMapping]*TrackData, len(mappings))
	for _, mapping := range mappings {
		tracks[mapping] = &TrackData{Data: map[log.ObjectRef]json.RawMessage{}}
	}
	return tracks
}

func seedObject(t *testing.T, track *TrackData, object *unstructured.Unstructured) {
	t.Helper()
	clone := object.DeepCopy()
	clone.SetResourceVersion("")
	raw, err := json.Marshal(clone)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	track.Data[log.KObj(clone)] = raw
}

func makePod(name, resourceVersion string, labels map[string]string) *unstructured.Unstructured {
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "default",
			ResourceVersion:   resourceVersion,
			CreationTimestamp: metav1.NewTime(testBaseTime.Add(time.Second)),
			Labels:            labels,
		},
		Spec: corev1.PodSpec{NodeName: "node-" + name},
	}
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pod)
	if err != nil {
		panic(err)
	}
	return &unstructured.Unstructured{Object: object}
}

func makeConfigMap(name, resourceVersion string, data map[string]string) *unstructured.Unstructured {
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", ResourceVersion: resourceVersion},
		Data:       data,
	}
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(cm)
	if err != nil {
		panic(err)
	}
	return &unstructured.Unstructured{Object: object}
}

func podModifiedEvent(name, resourceVersion string, labels map[string]string) watch.Event {
	return watch.Event{Type: watch.Modified, Object: makePod(name, resourceVersion, labels)}
}

func decodeDocs(t *testing.T, buf *bytes.Buffer) []*unstructured.Unstructured {
	t.Helper()
	decoder := utilsyaml.NewDecoder(bytes.NewReader(buf.Bytes()))
	var docs []*unstructured.Unstructured
	for {
		object, err := decoder.DecodeUnstructured()
		if err != nil {
			break
		}
		docs = append(docs, object)
	}
	return docs
}

func patches(docs []*unstructured.Unstructured) []*unstructured.Unstructured {
	var result []*unstructured.Unstructured
	for _, doc := range docs {
		if doc.GetKind() == recording.ResourcePatchType.Kind &&
			doc.GetAPIVersion() == recording.ResourcePatchType.APIVersion {
			result = append(result, doc)
		}
	}
	return result
}

func progressDocs(docs []*unstructured.Unstructured) []*unstructured.Unstructured {
	var result []*unstructured.Unstructured
	for _, doc := range docs {
		if doc.GetKind() == recording.RecordingProgressKind {
			result = append(result, doc)
		}
	}
	return result
}

// summarize renders the kinds of the encoded documents for failure messages.
func summarize(t *testing.T, docs []*unstructured.Unstructured) []string {
	t.Helper()
	kinds := make([]string, 0, len(docs))
	for _, doc := range docs {
		kinds = append(kinds, doc.GetKind())
	}
	return kinds
}

func patchLabel(doc *unstructured.Unstructured, key string) (string, bool) {
	template, ok := doc.Object["template"].(map[string]any)
	if !ok {
		return "", false
	}
	metadata, ok := template["metadata"].(map[string]any)
	if !ok {
		return "", false
	}
	labels, ok := metadata["labels"].(map[string]any)
	if !ok {
		return "", false
	}
	value, ok := labels[key].(string)
	return value, ok
}

func patchMethod(doc *unstructured.Unstructured) string {
	method, _ := doc.Object["method"].(string)
	return method
}

func lastProgress(t *testing.T, docs []*unstructured.Unstructured) map[string]string {
	t.Helper()
	boundaries := progressDocs(docs)
	if len(boundaries) == 0 {
		t.Fatalf("no progress boundary written")
	}
	positions, _ := boundaries[len(boundaries)-1].Object["positions"].([]any)
	result := map[string]string{}
	for _, position := range positions {
		entry := position.(map[string]any)
		resource := entry["resource"].(map[string]any)
		result[resource["resource"].(string)] = entry["resourceVersion"].(string)
	}
	return result
}

func stopAndWait(t *testing.T, cancel context.CancelFunc, done chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Record returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Record did not stop after cancellation")
	}
}

// TestRecordReconnectsFromReceivedPosition verifies that after a normal watch
// disconnect the watch is restarted from the last received position and that
// re-received events do not duplicate the timeline.
func TestRecordReconnectsFromReceivedPosition(t *testing.T) {
	ctx := t.Context()
	h := newRecorderHarness(t)

	tracks := mustTracks(h.podMap)
	tracks[h.podMap].ResourceVersion = "10"
	seedObject(t, tracks[h.podMap], makePod("a", "", map[string]string{"x": "1"}))

	first := newScriptedWatcher()
	second := newScriptedWatcher()
	h.queueWatchers("pods", first, second)

	buf, cancel, done := h.run(ctx, tracks)

	// First watch starts at the committed position and delivers one event.
	h.waitWatchStart(t, "pods", "10")
	first.send(podModifiedEvent("a", "11", map[string]string{"x": "2"}))
	h.clk.SetTime(testBaseTime.Add(time.Second))
	first.closeWatch()

	// The reconnect must continue from the last received position.
	h.waitWatchStart(t, "pods", "11")
	h.clk.SetTime(testBaseTime.Add(2 * time.Second))
	second.send(podModifiedEvent("a", "12", map[string]string{"x": "3"}))

	// The change received before the disconnect is only committed after the
	// reconnect watch covered it, so the timeline must not lose it.
	h.clk.SetTime(testBaseTime.Add(3 * time.Second))
	stopAndWait(t, cancel, done)

	docs := decodeDocs(t, buf)
	got := patches(docs)
	if len(got) != 2 {
		t.Fatalf("expected 2 patches without duplicates, got %d: %v", len(got), summarize(t, docs))
	}
	if patchMethod(got[0]) != "patch" || patchMethod(got[1]) != "patch" {
		t.Errorf("both events should be patches, got %q, %q", patchMethod(got[0]), patchMethod(got[1]))
	}
	if v, _ := patchLabel(got[0], "x"); v != "2" {
		t.Errorf("first patch label = %q, want 2", v)
	}
	if v, _ := patchLabel(got[1], "x"); v != "3" {
		t.Errorf("second patch label = %q, want 3", v)
	}

	if got, want := h.watchRV["pods"], []string{"10", "11"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("watch positions = %v, want %v", got, want)
	}

	final := lastProgress(t, docs)
	if final["pods"] != "12" {
		t.Errorf("final pods position = %q, want 12", final["pods"])
	}
}

// TestRecordResyncsAfterExpiredPosition verifies that an expired position
// triggers a relist whose net changes are recorded as patches, followed by a
// new watch at the list resource version rather than silently jumping ahead.
func TestRecordResyncsAfterExpiredPosition(t *testing.T) {
	ctx := t.Context()
	h := newRecorderHarness(t)

	tracks := mustTracks(h.podMap)
	tracks[h.podMap].ResourceVersion = "10"
	seedObject(t, tracks[h.podMap], makePod("a", "", map[string]string{"x": "1"}))
	seedObject(t, tracks[h.podMap], makePod("gone", "", map[string]string{"x": "1"}))

	first := newScriptedWatcher()
	second := newScriptedWatcher()
	h.queueWatchers("pods", first, second)
	// Current cluster state: a changed, b created, gone deleted.
	h.setListResult(
		makePod("a", "19", map[string]string{"x": "9"}),
		makePod("b", "20", map[string]string{"x": "new"}),
	)

	buf, cancel, done := h.run(ctx, tracks)

	h.waitWatchStart(t, "pods", "10")
	first.send(expiredStatus())
	h.clk.SetTime(testBaseTime.Add(time.Second))

	// The position is expired: the recorder must relist and continue watching
	// from the list resource version, not from the current moment.
	h.waitWatchStart(t, "pods", "20")
	h.clk.SetTime(testBaseTime.Add(2 * time.Second))
	second.send(podModifiedEvent("a", "21", map[string]string{"x": "10"}))

	stopAndWait(t, cancel, done)

	docs := decodeDocs(t, buf)
	got := patches(docs)
	// 3 net-change patches from the relist plus the event delivered by the
	// restarted watch.
	if len(got) != 4 {
		t.Fatalf("expected 4 patches, got %d: %v", len(got), summarize(t, docs))
	}
	methods := map[string]string{}
	for _, doc := range got {
		namespace, _ := doc.Object["target"].(map[string]any)["namespace"].(string)
		name, _ := doc.Object["target"].(map[string]any)["name"].(string)
		methods[namespace+"/"+name] = patchMethod(doc)
	}
	if methods["default/a"] != "patch" {
		t.Errorf("pod a method = %q, want patch", methods["default/a"])
	}
	if methods["default/b"] != "create" {
		t.Errorf("pod b method = %q, want create", methods["default/b"])
	}
	if methods["default/gone"] != "delete" {
		t.Errorf("pod gone method = %q, want delete", methods["default/gone"])
	}

	if len(h.listRV) == 0 {
		t.Errorf("expected a relist after expiration")
	}
	if got, want := h.watchRV["pods"], []string{"10", "20"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("watch positions = %v, want %v (must not silently jump ahead)", got, want)
	}
	final := lastProgress(t, docs)
	if final["pods"] != "21" {
		t.Errorf("final pods position = %q, want 21", final["pods"])
	}
}

// TestRecordResourcesAreIndependent verifies that rebuilding the watch of one
// resource kind neither blocks nor resets the other resource streams.
func TestRecordResourcesAreIndependent(t *testing.T) {
	ctx := t.Context()
	h := newRecorderHarness(t)

	tracks := mustTracks(h.podMap, h.cmMap)
	tracks[h.podMap].ResourceVersion = "10"
	tracks[h.cmMap].ResourceVersion = "10"

	podsFirst := newScriptedWatcher()
	podsSecond := newScriptedWatcher()
	configmapsFirst := newScriptedWatcher()
	h.queueWatchers("pods", podsFirst, podsSecond)
	h.queueWatchers("configmaps", configmapsFirst)
	h.setListResult(makePod("a", "19", map[string]string{"x": "1"}))

	buf, cancel, done := h.run(ctx, tracks)

	// Pods expire immediately and must go through a relist.
	h.waitWatchStart(t, "pods", "10")
	podsFirst.send(expiredStatus())
	// Meanwhile the configmap stream stays alive and keeps delivering.
	h.waitWatchStart(t, "configmaps", "10")
	h.clk.SetTime(testBaseTime.Add(2 * time.Second))
	configmapsFirst.send(watch.Event{Type: watch.Modified, Object: makeConfigMap("cm", "11", map[string]string{"k": "v"})})
	h.waitWatchStart(t, "pods", "20")

	stopAndWait(t, cancel, done)

	docs := decodeDocs(t, buf)
	got := patches(docs)
	if len(got) != 2 {
		t.Fatalf("expected one patch per resource, got %d: %v", len(got), summarize(t, docs))
	}
	kinds := map[string]bool{}
	for _, doc := range got {
		kinds[doc.Object["resource"].(map[string]any)["resource"].(string)] = true
	}
	if !kinds["pods"] || !kinds["configmaps"] {
		t.Errorf("expected patches of both pods and configmaps during the pods resync, got %v", kinds)
	}

	if got := h.watchRV["configmaps"]; len(got) != 1 || got[0] != "10" {
		t.Errorf("configmap watch should not be rebuilt, restarts = %v", got)
	}
	final := lastProgress(t, docs)
	if final["pods"] != "20" {
		t.Errorf("pods position = %q, want 20", final["pods"])
	}
	if final["configmaps"] != "11" {
		t.Errorf("configmaps position = %q, want 11", final["configmaps"])
	}
}

// TestPrepareResumeRebuildsCommittedState verifies that the resumed tracks
// reflect the last committed object state and position and that events
// re-obtained from the server after the boundary are not duplicated.
func TestPrepareResumeRebuildsCommittedState(t *testing.T) {
	ctx := t.Context()
	h := newRecorderHarness(t)

	start := testBaseTime
	var buffer bytes.Buffer
	encoder := utilsyaml.NewEncoder(&buffer)
	mustEncode(t, encoder, recording.NewRecording([]schema.GroupVersionResource{testPodGVR}, start))
	// The initial object stores timestamps as relative offsets, exactly like
	// the write hook emits them into a real recording file.
	mustEncode(t, encoder, map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":              "a",
			"namespace":         "default",
			"resourceVersion":   "5",
			"creationTimestamp": "$(time-offset-nanosecond 1000000000)",
			"labels":            map[string]any{"x": "1"},
		},
		"spec": map[string]any{"nodeName": "node-a"},
	})
	mustEncode(t, encoder, recording.NewRecordingProgress(map[schema.GroupVersionResource]string{testPodGVR: "10"}))
	mustEncode(t, encoder, committedPatch("default", "a", "2", start.Add(5*time.Second)))
	mustEncode(t, encoder, recording.NewRecordingProgress(map[schema.GroupVersionResource]string{testPodGVR: "12"}))
	// Uncommitted tail: received but never bounded.
	mustEncode(t, encoder, committedPatch("default", "a", "3", start.Add(6*time.Second)))

	data, err := recording.ReadResumeData(&buffer)
	if err != nil {
		t.Fatalf("ReadResumeData: %v", err)
	}

	result, err := h.saver.PrepareResume(ctx, data, []*meta.RESTMapping{h.podMap})
	if err != nil {
		t.Fatalf("PrepareResume: %v", err)
	}
	if got, want := result.StartTime, start; !got.Equal(want) {
		t.Errorf("start time = %v, want %v", got, want)
	}
	track := result.Tracks[h.podMap]
	if track.ResourceVersion != "12" {
		t.Errorf("resumed position = %q, want 12", track.ResourceVersion)
	}
	var state unstructured.Unstructured
	if err := json.Unmarshal(track.Data[log.KRef("default", "a")], &state.Object); err != nil {
		t.Fatalf("unmarshal tracked state: %v", err)
	}
	if got := state.GetLabels()["x"]; got != "2" {
		t.Errorf("committed state label = %q, want 2 (uncommitted change must be dropped)", got)
	}
	wantCreation := start.Add(time.Second).UTC().Format(time.RFC3339)
	if got := state.GetCreationTimestamp().UTC().Format(time.RFC3339); got != wantCreation {
		t.Errorf("committed creationTimestamp = %q, want %q", got, wantCreation)
	}

	// The server re-delivers the change that was received but never committed.
	first := newScriptedWatcher()
	h.queueWatchers("pods", first)
	buf, cancel, done := h.run(ctx, result.Tracks)

	h.waitWatchStart(t, "pods", "12")
	h.clk.SetTime(start.Add(7 * time.Second))
	first.send(podModifiedEvent("a", "13", map[string]string{"x": "3"}))

	stopAndWait(t, cancel, done)

	docs := decodeDocs(t, buf)
	got := patches(docs)
	if len(got) != 1 || patchMethod(got[0]) != "patch" {
		t.Fatalf("expected exactly one resumed patch, got %d: %v", len(got), summarize(t, docs))
	}
	if v, _ := patchLabel(got[0], "x"); v != "3" {
		t.Errorf("resumed patch label = %q, want 3", v)
	}
	// The resumed diff must not see the reverted creationTimestamp as a change.
	if template, _ := got[0].Object["template"].(map[string]any); template != nil {
		if metadata, _ := template["metadata"].(map[string]any); metadata != nil {
			if _, changed := metadata["creationTimestamp"]; changed {
				t.Errorf("resumed patch must not contain a creationTimestamp diff: %s", template["metadata"])
			}
		}
	}
	if h.watchRV["pods"][0] != "12" {
		t.Errorf("resumed watch must start at committed position 12, got %q", h.watchRV["pods"][0])
	}

	// The full timeline is gap-free and duplicate-free.
	allDocs := append(append([]*unstructured.Unstructured{}, data.Documents...), docs...)
	allPatches := patches(allDocs)
	if len(allPatches) != 2 {
		t.Fatalf("full timeline patches = %d, want 2 (x=2 committed, x=3 resumed)", len(allPatches))
	}
	if v, _ := patchLabel(allPatches[0], "x"); v != "2" {
		t.Errorf("first timeline patch label = %q, want 2", v)
	}
	if v, _ := patchLabel(allPatches[1], "x"); v != "3" {
		t.Errorf("second timeline patch label = %q, want 3", v)
	}
	final := lastProgress(t, allDocs)
	if final["pods"] != "13" {
		t.Errorf("final position = %q, want 13", final["pods"])
	}
}

func TestPrepareResumeRejectsFilterMismatch(t *testing.T) {
	ctx := t.Context()
	h := newRecorderHarness(t)

	var buffer bytes.Buffer
	encoder := utilsyaml.NewEncoder(&buffer)
	mustEncode(t, encoder, recording.NewRecording([]schema.GroupVersionResource{testPodGVR}, testBaseTime))
	mustEncode(t, encoder, recording.NewRecordingProgress(map[schema.GroupVersionResource]string{testPodGVR: "1"}))

	data, err := recording.ReadResumeData(&buffer)
	if err != nil {
		t.Fatalf("ReadResumeData: %v", err)
	}
	_, err = h.saver.PrepareResume(ctx, data, []*meta.RESTMapping{h.podMap, h.cmMap})
	if !errors.Is(err, ErrFilterScopeMismatch) {
		t.Fatalf("err = %v, want ErrFilterScopeMismatch", err)
	}
}

func committedPatch(namespace, name, label string, at time.Time) *recording.ResourcePatch {
	patch := &recording.ResourcePatch{
		TypeMeta:           recording.ResourcePatchType,
		Target:             v1alpha1.Target{Name: name, Namespace: namespace},
		DurationNanosecond: at.Sub(testBaseTime),
		Method:             v1alpha1.PatchMethodPatch,
		Template:           json.RawMessage(fmt.Sprintf(`{"metadata":{"labels":{"x":%q}}}`, label)),
	}
	patch.SetTargetGroupVersionResource(testPodGVR)
	return patch
}

func mustEncode(t *testing.T, encoder *utilsyaml.Encoder, object any) {
	t.Helper()
	if err := encoder.Encode(object); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

func (h *recorderHarness) waitWatchStart(t *testing.T, resource, resourceVersion string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		for _, rv := range h.watchRV[resource] {
			if rv == resourceVersion {
				h.mu.Unlock()
				return
			}
		}
		h.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
	}
	h.mu.Lock()
	starts := h.watchRV[resource]
	h.mu.Unlock()
	t.Fatalf("watch for %q never started at resource version %q (starts: %v)", resource, resourceVersion, starts)
}
