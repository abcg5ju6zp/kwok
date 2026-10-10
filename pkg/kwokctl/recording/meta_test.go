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

package recording

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/kwok/pkg/utils/yaml"
)

var (
	podGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	cmGVR  = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
)

func TestReadResumeDataKeepsCompletePrefix(t *testing.T) {
	startTime := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)

	meta := NewRecording([]schema.GroupVersionResource{podGVR, cmGVR}, startTime)
	if err := encoder.Encode(meta); err != nil {
		t.Fatalf("encode meta: %v", err)
	}
	if err := encoder.Encode(newUnstructured("v1", "Pod", "default", "initial")); err != nil {
		t.Fatalf("encode object: %v", err)
	}
	if err := encoder.Encode(newPatch("default", "pod-1", 1)); err != nil {
		t.Fatalf("encode patch: %v", err)
	}
	if err := encoder.Encode(NewRecordingProgress(map[schema.GroupVersionResource]string{
		podGVR: "10",
		cmGVR:  "5",
	})); err != nil {
		t.Fatalf("encode progress: %v", err)
	}
	// Committed later: pods advances, configmaps does not report a position.
	if err := encoder.Encode(newPatch("default", "pod-2", 2)); err != nil {
		t.Fatalf("encode patch: %v", err)
	}
	if err := encoder.Encode(NewRecordingProgress(map[schema.GroupVersionResource]string{
		podGVR: "12",
	})); err != nil {
		t.Fatalf("encode progress: %v", err)
	}
	// An incomplete tail: received but never bounded by a progress document.
	if err := encoder.Encode(newPatch("default", "pod-3", 3)); err != nil {
		t.Fatalf("encode patch: %v", err)
	}
	if _, err := buf.WriteString("\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: bro"); err != nil {
		t.Fatalf("write tail: %v", err)
	}

	data, err := ReadResumeData(&buf)
	if err != nil {
		t.Fatalf("ReadResumeData: %v", err)
	}

	if !data.Meta.MatchesFilters([]schema.GroupVersionResource{podGVR, cmGVR}) {
		t.Errorf("filters should match")
	}
	if data.Meta.MatchesFilters([]schema.GroupVersionResource{podGVR}) {
		t.Errorf("filters must not match a subset")
	}
	if data.Meta.MatchesFilters([]schema.GroupVersionResource{podGVR, cmGVR, {Group: "apps", Version: "v1", Resource: "deployments"}}) {
		t.Errorf("filters must not match a superset")
	}
	if got, want := data.Meta.StartTime(), startTime; !got.Equal(want) {
		t.Errorf("start time = %v, want %v", got, want)
	}
	if got, want := data.Positions[podGVR], "12"; got != want {
		t.Errorf("pods position = %q, want %q", got, want)
	}
	if got, want := data.Positions[cmGVR], "5"; got != want {
		t.Errorf("configmaps position = %q, want %q", got, want)
	}

	// Documents end at the last complete progress boundary; the uncommitted
	// patch and the truncated document are discarded.
	last := data.Documents[len(data.Documents)-1]
	if last.GetKind() != RecordingProgressKind {
		t.Errorf("last retained document = %q, want progress boundary", last.GetKind())
	}
	if len(data.Documents) != 6 {
		var kinds []string
		for _, doc := range data.Documents {
			kinds = append(kinds, doc.GetKind())
		}
		t.Errorf("retained %d documents %v, want 6 (meta, object, patch, progress, patch, progress)", len(data.Documents), kinds)
	}
}

func TestReadResumeDataGzip(t *testing.T) {
	startTime := time.Unix(1_700_000_000, 0)

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	encoder := yaml.NewEncoder(gz)
	if err := encoder.Encode(NewRecording([]schema.GroupVersionResource{podGVR}, startTime)); err != nil {
		t.Fatalf("encode meta: %v", err)
	}
	if err := encoder.Encode(NewRecordingProgress(map[schema.GroupVersionResource]string{podGVR: "7"})); err != nil {
		t.Fatalf("encode progress: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	// Append a truncated gzip member to simulate a crash mid-write.
	tail := gzip.NewWriter(&compressed)
	if _, err := tail.Write([]byte("---\napiVersion: v1\nkind: Pod\nincomplete")); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	// Intentionally do not close tail.

	reader, err := gzip.NewReader(&compressed)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	data, err := ReadResumeData(reader)
	if err != nil {
		t.Fatalf("ReadResumeData: %v", err)
	}
	if got := data.Positions[podGVR]; got != "7" {
		t.Errorf("position = %q, want 7", got)
	}
	if len(data.Documents) != 2 {
		t.Errorf("retained %d documents, want 2", len(data.Documents))
	}
}

func TestReadResumeDataOldFormat(t *testing.T) {
	// Files without a Recording head document must keep replaying, they are
	// just not resumable.
	stream := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: initial\n"
	if _, err := ReadResumeData(strings.NewReader(stream)); !errors.Is(err, ErrNotResumable) {
		t.Fatalf("err = %v, want ErrNotResumable", err)
	}
}

func TestReadResumeDataWithoutBoundary(t *testing.T) {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	if err := encoder.Encode(NewRecording([]schema.GroupVersionResource{podGVR}, time.Now())); err != nil {
		t.Fatalf("encode meta: %v", err)
	}
	if err := encoder.Encode(newPatch("default", "pod-1", 1)); err != nil {
		t.Fatalf("encode patch: %v", err)
	}
	if _, err := ReadResumeData(&buf); !errors.Is(err, ErrNoCompleteBoundary) {
		t.Fatalf("err = %v, want ErrNoCompleteBoundary", err)
	}
}

func TestIsRecordingDocument(t *testing.T) {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion(RecordingAPIVersion)
	obj.SetKind(RecordingProgressKind)
	if !IsRecordingDocument(obj) {
		t.Errorf("progress document should be recognized")
	}
	obj.SetKind("Pod")
	if IsRecordingDocument(obj) {
		t.Errorf("pod should not be recognized as recording document")
	}
}

func newPatch(namespace, name string, duration time.Duration) *ResourcePatch {
	patch := &ResourcePatch{
		TypeMeta:            ResourcePatchType,
		DurationNanosecond:  duration,
		Method:              "patch",
		Template:            []byte(`{"metadata":{"labels":{"a":"b"}}}`),
	}
	patch.SetTargetName(name, namespace)
	patch.SetTargetGroupVersionResource(podGVR)
	return patch
}

func newUnstructured(apiVersion, kind, namespace, name string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{}}
	obj.SetAPIVersion(apiVersion)
	obj.SetKind(kind)
	obj.SetNamespace(namespace)
	obj.SetName(name)
	return obj
}
