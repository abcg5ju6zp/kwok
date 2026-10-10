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

package export

import (
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/kwok/pkg/kwokctl/recording"
)

var testPodGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

// TestRewriteRecordingPrefixRoundTrip verifies that resuming rewrites only the
// committed prefix, that appended events continue the file correctly and that
// the resulting file scans with merged positions and no duplicated patches.
func TestRewriteRecordingPrefixRoundTrip(t *testing.T) {
	for _, ext := range []string{".yaml", ".yaml.gz"} {
		t.Run(ext, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recording"+ext)
			startTime := time.Unix(1_700_000_000, 0)

			writeSourceRecording(t, path, startTime)

			data, err := scanRecording(path)
			if err != nil {
				t.Fatalf("scan original recording: %v", err)
			}
			if got := data.Positions[testPodGVR]; got != "12" {
				t.Fatalf("original position = %q, want 12", got)
			}
			// meta, initial object, first boundary, patch, second boundary.
			if len(data.Documents) != 5 {
				t.Fatalf("committed documents = %d, want 5", len(data.Documents))
			}

			writer, err := rewriteRecordingPrefix(path, startTime, data.Documents)
			if err != nil {
				t.Fatalf("rewrite prefix: %v", err)
			}

			// Simulate the resumed session: append one patch and a new
			// boundary, then close the file cleanly.
			appended := recording.NewRecordingProgress(map[schema.GroupVersionResource]string{testPodGVR: "13"})
			if err := writer.encoder.Encode(appended); err != nil {
				t.Fatalf("encode appended boundary: %v", err)
			}
			if err := writer.flush(); err != nil {
				t.Fatalf("flush appended boundary: %v", err)
			}
			writer.close()

			resumed, err := scanRecording(path)
			if err != nil {
				t.Fatalf("scan resumed recording: %v", err)
			}
			if got := resumed.Positions[testPodGVR]; got != "13" {
				t.Errorf("resumed position = %q, want 13", got)
			}
			if len(resumed.Documents) != 6 {
				var kinds []string
				for _, doc := range resumed.Documents {
					kinds = append(kinds, doc.GetKind())
				}
				t.Errorf("resumed documents = %d (%v), want 6", len(resumed.Documents), kinds)
			}

			var boundaries, patches int
			for _, doc := range resumed.Documents {
				switch doc.GetKind() {
				case recording.RecordingProgressKind:
					boundaries++
				case recording.ResourcePatchType.Kind:
					patches++
				}
			}
			if boundaries != 3 {
				t.Errorf("progress boundaries = %d, want 3", boundaries)
			}
			if patches != 1 {
				t.Errorf("resource patches in retained prefix = %d, want 1 (uncommitted tail must be dropped)", patches)
			}
		})
	}
}

func writeSourceRecording(t *testing.T, path string, startTime time.Time) {
	t.Helper()

	writer, err := openRecordingWriter(path, startTime)
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}

	encode := func(object any) {
		t.Helper()
		if err := writer.encoder.Encode(object); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}

	encode(recording.NewRecording([]schema.GroupVersionResource{testPodGVR}, startTime))
	encode(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "a",
			"namespace": "default",
		},
	})
	encode(recording.NewRecordingProgress(map[schema.GroupVersionResource]string{testPodGVR: "10"}))

	patch := &recording.ResourcePatch{
		TypeMeta:            recording.ResourcePatchType,
		DurationNanosecond:  5 * time.Second,
		Method:              "patch",
		Template:            []byte(`{"metadata":{"labels":{"x":"2"}}}`),
	}
	patch.SetTargetGroupVersionResource(testPodGVR)
	patch.SetTargetName("a", "default")
	encode(patch)
	encode(recording.NewRecordingProgress(map[schema.GroupVersionResource]string{testPodGVR: "12"}))

	// Received but never bounded by a progress document: an incomplete tail.
	uncommitted := &recording.ResourcePatch{
		TypeMeta:           recording.ResourcePatchType,
		DurationNanosecond: 6 * time.Second,
		Method:             "patch",
		Template:           []byte(`{"metadata":{"labels":{"x":"3"}}}`),
	}
	uncommitted.SetTargetGroupVersionResource(testPodGVR)
	uncommitted.SetTargetName("a", "default")
	encode(uncommitted)

	writer.close()
}
