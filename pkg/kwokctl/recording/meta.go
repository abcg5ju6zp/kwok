/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package recording

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/kwok/pkg/utils/yaml"
)

const (
	// GroupName is the group name of the recording API.
	GroupName = "recording.kwok.x-k8s.io"

	// RecordingKind is the kind of the recording metadata.
	RecordingKind = "Recording"
	// RecordingProgressKind is the kind of the recording progress boundary.
	RecordingProgressKind = "RecordingProgress"
)

// RecordingAPIVersion is the API version of the recording documents.
var RecordingAPIVersion = schema.GroupVersion{
	Group:   GroupName,
	Version: "v1alpha1",
}.String()

// RecordingType is the type of the Recording.
var RecordingType = metav1.TypeMeta{
	Kind:       RecordingKind,
	APIVersion: RecordingAPIVersion,
}

// RecordingProgressType is the type of the RecordingProgress.
var RecordingProgressType = metav1.TypeMeta{
	Kind:       RecordingProgressKind,
	APIVersion: RecordingAPIVersion,
}

// GroupVersionResource identifies a resource kind of a recorded cluster.
type GroupVersionResource struct {
	Group    string `json:"group,omitempty"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// Key converts the GroupVersionResource to a schema.GroupVersionResource.
func (r GroupVersionResource) Key() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    r.Group,
		Version:  r.Version,
		Resource: r.Resource,
	}
}

// FromGroupVersionResource converts a schema.GroupVersionResource to a GroupVersionResource.
func FromGroupVersionResource(gvr schema.GroupVersionResource) GroupVersionResource {
	return GroupVersionResource{
		Group:    gvr.Group,
		Version:  gvr.Version,
		Resource: gvr.Resource,
	}
}

// Recording is the head document of a resumable recording file.
// It persists the filter scope of the recording and the base time
// used to compute the relative durations of the recorded patches.
type Recording struct {
	metav1.TypeMeta `json:",inline"`

	// Filters is the filter scope of the recording.
	// A recording can only be resumed with exactly the same filter scope.
	Filters []GroupVersionResource `json:"filters"`
	// StartTimeNanosecond is the base time of the recording in nanoseconds
	// since the unix epoch. It is stored as an integer so that it survives
	// the relative time rewrite applied to the stream.
	StartTimeNanosecond int64 `json:"startTimeNanosecond"`
}

// NewRecording creates a new Recording metadata document.
func NewRecording(filters []schema.GroupVersionResource, startTime time.Time) *Recording {
	recordingFilters := make([]GroupVersionResource, 0, len(filters))
	for _, f := range filters {
		recordingFilters = append(recordingFilters, FromGroupVersionResource(f))
	}
	sort.Slice(recordingFilters, func(i, j int) bool {
		return lessGroupVersionResource(recordingFilters[i], recordingFilters[j])
	})
	return &Recording{
		TypeMeta:            RecordingType,
		Filters:             recordingFilters,
		StartTimeNanosecond: startTime.UnixNano(),
	}
}

// StartTime returns the base time of the recording.
func (r *Recording) StartTime() time.Time {
	return time.Unix(0, r.StartTimeNanosecond)
}

// FilterSet returns the filter scope as a set keyed by schema.GroupVersionResource.
func (r *Recording) FilterSet() map[schema.GroupVersionResource]struct{} {
	filters := make(map[schema.GroupVersionResource]struct{}, len(r.Filters))
	for _, f := range r.Filters {
		filters[f.Key()] = struct{}{}
	}
	return filters
}

// MatchesFilters reports whether the given filter scope is exactly the one
// stored in the recording.
func (r *Recording) MatchesFilters(filters []schema.GroupVersionResource) bool {
	set := r.FilterSet()
	if len(set) != len(filters) {
		return false
	}
	for _, f := range filters {
		if _, ok := set[f]; !ok {
			return false
		}
	}
	return true
}

// RecordingPosition is the last committed position for a single resource kind.
type RecordingPosition struct {
	// Resource is the resource kind the position belongs to.
	Resource GroupVersionResource `json:"resource"`
	// ResourceVersion is the last resource version that is fully committed
	// for the resource kind.
	ResourceVersion string `json:"resourceVersion"`
}

// RecordingProgress is a commit boundary written into the recording stream.
// Every document preceding a progress document is complete and durable.
// The documents following the last progress document are an incomplete tail
// that is discarded when the recording is resumed.
type RecordingProgress struct {
	metav1.TypeMeta `json:",inline"`

	// Positions is the last committed position per resource kind.
	Positions []RecordingPosition `json:"positions,omitempty"`
}

// NewRecordingProgress creates a new RecordingProgress boundary document.
func NewRecordingProgress(positions map[schema.GroupVersionResource]string) *RecordingProgress {
	progress := &RecordingProgress{
		TypeMeta:  RecordingProgressType,
		Positions: make([]RecordingPosition, 0, len(positions)),
	}
	for gvr, resourceVersion := range positions {
		if resourceVersion == "" {
			continue
		}
		progress.Positions = append(progress.Positions, RecordingPosition{
			Resource:        FromGroupVersionResource(gvr),
			ResourceVersion: resourceVersion,
		})
	}
	sort.Slice(progress.Positions, func(i, j int) bool {
		return lessGroupVersionResource(progress.Positions[i].Resource, progress.Positions[j].Resource)
	})
	return progress
}

// PositionsMap returns the positions as a map keyed by schema.GroupVersionResource.
func (p *RecordingProgress) PositionsMap() map[schema.GroupVersionResource]string {
	positions := make(map[schema.GroupVersionResource]string, len(p.Positions))
	for _, position := range p.Positions {
		positions[position.Resource.Key()] = position.ResourceVersion
	}
	return positions
}

func lessGroupVersionResource(a, b GroupVersionResource) bool {
	if a.Group != b.Group {
		return a.Group < b.Group
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return a.Resource < b.Resource
}

// IsRecordingDocument reports whether the document is a recording metadata
// or progress document. Such documents are transparent to replay.
func IsRecordingDocument(obj *unstructured.Unstructured) bool {
	return IsRecordingKind(obj.GetAPIVersion(), obj.GetKind())
}

// IsRecordingKind reports whether the apiVersion/kind pair is a recording document.
func IsRecordingKind(apiVersion, kind string) bool {
	if apiVersion != RecordingAPIVersion {
		return false
	}
	return kind == RecordingKind || kind == RecordingProgressKind
}

// Errors returned by ReadResumeData.
var (
	// ErrNotResumable is returned when the file does not contain a Recording
	// head document and therefore cannot be resumed.
	ErrNotResumable = errors.New("recording is not resumable: recording metadata not found")
	// ErrNoCompleteBoundary is returned when the file contains a Recording
	// head but no complete progress boundary.
	ErrNoCompleteBoundary = errors.New("recording has no complete boundary to resume from")
)

// ResumeData is the result of scanning a recording file for resumption.
type ResumeData struct {
	// Meta is the head metadata of the recording.
	Meta *Recording
	// Documents are the complete documents up to (and including) the last
	// complete progress boundary.
	Documents []*unstructured.Unstructured
	// Positions is the last committed position per resource kind, merged
	// across all progress boundaries.
	Positions map[schema.GroupVersionResource]string
}

// ReadResumeData scans a recording stream and returns the resumable prefix
// of the recording, i.e. the metadata and every complete document up to the
// last complete progress boundary. The incomplete tail (documents that were
// being written when the recorder stopped) is ignored.
//
// The stream is split into documents before decoding. This keeps the scan
// working when a compressed stream ends abruptly: a truncated gzip member
// still yields all its inflated prefix, and every complete document in it can
// be decoded independently of the broken tail.
func ReadResumeData(r io.Reader) (*ResumeData, error) {
	// A truncated compressed stream returns its inflated prefix together
	// with the read error; the prefix is all we need.
	raw, _ := io.ReadAll(r)

	var (
		meta      *Recording
		documents []*unstructured.Unstructured
		// boundary is the index of the last complete progress boundary.
		boundary  = -1
		positions = map[schema.GroupVersionResource]string{}
	)

	for _, segment := range splitYAMLDocuments(raw) {
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(segment, obj); err != nil {
			// The tail is truncated or corrupt: keep everything decoded so far.
			break
		}

		if len(documents) == 0 {
			// A resumable recording always starts with a Recording head document.
			if obj.GetAPIVersion() != RecordingAPIVersion || obj.GetKind() != RecordingKind {
				return nil, ErrNotResumable
			}
			recording := &Recording{}
			if err := convertUnstructured(obj, recording); err != nil {
				return nil, fmt.Errorf("failed to decode recording metadata: %w", err)
			}
			meta = recording
		} else if obj.GetAPIVersion() == RecordingAPIVersion && obj.GetKind() == RecordingProgressKind {
			progress := &RecordingProgress{}
			if err := convertUnstructured(obj, progress); err != nil {
				// A corrupt boundary cannot be trusted; treat the rest as tail.
				break
			}
			for gvr, resourceVersion := range progress.PositionsMap() {
				if resourceVersionGreater(resourceVersion, positions[gvr]) {
					positions[gvr] = resourceVersion
				}
			}
			boundary = len(documents)
		}
		documents = append(documents, obj)
	}

	if meta == nil {
		return nil, ErrNotResumable
	}
	if boundary < 0 {
		return nil, ErrNoCompleteBoundary
	}

	return &ResumeData{
		Meta:      meta,
		Documents: documents[:boundary+1],
		Positions: positions,
	}, nil
}

var yamlDocumentSeparator = regexp.MustCompile(`(?m)^---[ \t]*\r?$`)

// splitYAMLDocuments splits a YAML stream into its individual documents.
func splitYAMLDocuments(raw []byte) [][]byte {
	parts := yamlDocumentSeparator.Split(string(raw), -1)
	documents := make([][]byte, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "..." {
			continue
		}
		documents = append(documents, []byte(part))
	}
	return documents
}

func convertUnstructured(obj *unstructured.Unstructured, into any) error {
	data, err := json.Marshal(obj.Object)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}

// resourceVersionGreater reports whether resource version a is greater than b.
// Resource versions are compared numerically when possible.
func resourceVersionGreater(a, b string) bool {
	if a == "" {
		return false
	}
	if b == "" {
		return true
	}
	ai, errA := strconv.ParseUint(a, 10, 64)
	bi, errB := strconv.ParseUint(b, 10, 64)
	if errA == nil && errB == nil {
		return ai > bi
	}
	return a > b
}
