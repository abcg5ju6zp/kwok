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
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/strategicpatch"

	"sigs.k8s.io/kwok/pkg/apis/action/v1alpha1"
	"sigs.k8s.io/kwok/pkg/kwokctl/recording"
	"sigs.k8s.io/kwok/pkg/log"
)

// ErrFilterScopeMismatch is returned when a resume request uses a different
// filter scope than the original recording.
var ErrFilterScopeMismatch = fmt.Errorf("filter scope does not match the recording")

// ResumeResult is the result of preparing a recording resume.
type ResumeResult struct {
	// Tracks contains the committed object state and the last committed
	// position for every resource kind.
	Tracks map[*meta.RESTMapping]*TrackData
	// StartTime is the base time of the original recording.
	StartTime time.Time
}

// PrepareResume validates the filter scope of a resume request and rebuilds
// the committed object state and the last committed position of every
// resource kind from the complete documents of the recording.
func (s *Saver) PrepareResume(ctx context.Context, data *recording.ResumeData, filters []*meta.RESTMapping) (*ResumeResult, error) {
	logger := log.FromContext(ctx)

	requested := make([]schema.GroupVersionResource, 0, len(filters))
	byGVR := make(map[schema.GroupVersionResource]*meta.RESTMapping, len(filters))
	byGVK := make(map[schema.GroupVersionKind]*meta.RESTMapping, len(filters))
	for _, rm := range filters {
		requested = append(requested, rm.Resource)
		byGVR[rm.Resource] = rm
		byGVK[rm.GroupVersionKind] = rm
	}

	if !data.Meta.MatchesFilters(requested) {
		return nil, fmt.Errorf("%w: recording filters %v, requested filters %v",
			ErrFilterScopeMismatch,
			formatRecordingMetaFilters(data.Meta.Filters),
			formatSchemaFilters(requested),
		)
	}

	tracks := make(map[*meta.RESTMapping]*TrackData, len(filters))
	for _, rm := range filters {
		tracks[rm] = &TrackData{
			Data:            map[log.ObjectRef]json.RawMessage{},
			ResourceVersion: data.Positions[rm.Resource],
		}
	}

	baseTime := data.Meta.StartTime()

	// The first document is the Recording metadata; the rest are the
	// committed initial state and resource patches.
	for _, obj := range data.Documents[1:] {
		if recording.IsRecordingDocument(obj) {
			continue
		}

		if obj.GetKind() == recording.ResourcePatchType.Kind &&
			obj.GetAPIVersion() == recording.ResourcePatchType.APIVersion {
			if err := s.applyCommittedPatch(baseTime, obj, byGVR, tracks); err != nil {
				logger.Warn("Skipped invalid committed resource patch",
					"err", err,
				)
			}
			continue
		}

		// Initial state object.
		rm := byGVK[obj.GroupVersionKind()]
		if rm == nil {
			continue
		}
		obj.SetResourceVersion("")
		raw, err := json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal committed object: %w", err)
		}
		// The file stores timestamps as offsets from the recording base
		// time; restore them at second precision, matching the JSON shape of
		// objects received from the API server, so that later diffs compare
		// against the same shape the recorder had in memory.
		raw = recording.RevertTimeFromRelativeWithFormat(baseTime, time.RFC3339, raw)
		tracks[rm].Data[log.KObj(obj)] = raw
	}

	return &ResumeResult{
		Tracks:    tracks,
		StartTime: baseTime,
	}, nil
}

func (s *Saver) applyCommittedPatch(baseTime time.Time, obj *unstructured.Unstructured, byGVR map[schema.GroupVersionResource]*meta.RESTMapping, tracks map[*meta.RESTMapping]*TrackData) error {
	data, err := json.Marshal(obj.Object)
	if err != nil {
		return err
	}
	// See PrepareResume: timestamps are stored as relative offsets in the
	// file and must be restored before the patch is applied to the state.
	data = recording.RevertTimeFromRelativeWithFormat(baseTime, time.RFC3339, data)
	var patch recording.ResourcePatch
	if err := json.Unmarshal(data, &patch); err != nil {
		return err
	}

	gvr := patch.GetTargetGroupVersionResource()
	rm := byGVR[gvr]
	if rm == nil {
		return fmt.Errorf("unknown resource %s", gvr)
	}
	track := tracks[rm].Data
	key := log.KRef(patch.Target.Namespace, patch.Target.Name)

	switch patch.Method {
	case v1alpha1.PatchMethodCreate:
		track[key] = patch.Template
	case v1alpha1.PatchMethodDelete:
		delete(track, key)
	case v1alpha1.PatchMethodPatch:
		patchMeta, err := s.patchMetaSchema.Lookup(gvr)
		if err != nil {
			return err
		}
		merged, err := strategicpatch.StrategicMergePatchUsingLookupPatchMeta(track[key], patch.Template, patchMeta)
		if err != nil {
			return err
		}
		track[key] = merged
	default:
		return fmt.Errorf("unknown patch method %q", patch.Method)
	}
	return nil
}

func formatRecordingMetaFilters(filters []recording.GroupVersionResource) []string {
	result := make([]string, 0, len(filters))
	for _, f := range filters {
		result = append(result, f.Key().String())
	}
	sort.Strings(result)
	return result
}

func formatSchemaFilters(filters []schema.GroupVersionResource) []string {
	result := make([]string, 0, len(filters))
	for _, f := range filters {
		result = append(result, f.String())
	}
	sort.Strings(result)
	return result
}
