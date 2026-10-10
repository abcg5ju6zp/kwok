/*
Copyright 2023 The Kubernetes Authors.

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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/pager"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/clock"

	"sigs.k8s.io/kwok/pkg/kwokctl/recording"
	"sigs.k8s.io/kwok/pkg/log"
	"sigs.k8s.io/kwok/pkg/utils/client"
	"sigs.k8s.io/kwok/pkg/utils/heap"
	"sigs.k8s.io/kwok/pkg/utils/patch"
	"sigs.k8s.io/kwok/pkg/utils/queue"
	"sigs.k8s.io/kwok/pkg/utils/wait"
	"sigs.k8s.io/kwok/pkg/utils/yaml"
)

// PagerConfig is the configuration of the list pager.
// It defines the page size and the page buffer size of the list pager.
type PagerConfig struct {
	PageSize       int64
	PageBufferSize int32
}

// SaveConfig is the a combination of the impersonation config
// and the PagerConfig.
type SaveConfig struct {
	Clientset   client.Clientset
	PagerConfig *PagerConfig
	Filters     []*meta.RESTMapping
}

// Saver is a snapshot saver.
type Saver struct {
	dynamicClient   dynamic.Interface
	saveConfig      SaveConfig
	patchMetaSchema patchMetaLookup

	clock clock.PassiveClock
}

// patchMetaLookup looks up the strategic patch metadata of a resource.
type patchMetaLookup interface {
	Lookup(gvr schema.GroupVersionResource) (strategicpatch.LookupPatchMeta, error)
}

// NewSaver creates a new snapshot saver.
func NewSaver(saveConfig SaveConfig) (*Saver, error) {
	dynamicClient, err := saveConfig.Clientset.ToDynamicClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	restConfig, err := saveConfig.Clientset.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get rest config: %w", err)
	}

	restConfig.GroupVersion = &schema.GroupVersion{}
	restClient, err := rest.RESTClientFor(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create rest client: %w", err)
	}

	patchMetaSchema := patch.NewPatchMetaFromOpenAPI3(restClient)

	return &Saver{
		saveConfig:      saveConfig,
		patchMetaSchema: patchMetaSchema,
		dynamicClient:   dynamicClient,
		clock:           clock.RealClock{},
	}, nil
}

// Save saves the snapshot of cluster
func (s *Saver) Save(ctx context.Context, encoder *yaml.Encoder, tracks map[*meta.RESTMapping]*TrackData) error {
	logger := log.FromContext(ctx)

	if tracks != nil {
		for _, rm := range s.saveConfig.Filters {
			tracks[rm] = &TrackData{
				Data: map[log.ObjectRef]json.RawMessage{},
			}
		}
	}

	startTime := time.Now()
	totalCounter := 0
	for _, rm := range s.saveConfig.Filters {
		gvr := rm.Resource
		nri := s.dynamicClient.Resource(gvr)
		logger := logger.With(
			"resource", gvr.Resource,
		)

		start := time.Now()
		page := 0

		latestResourceVersion := ""
		listPager := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			var list runtime.Object
			var err error
			page++
			logger := logger.With(
				"page", page,
				"limit", opts.Limit,
			)
			logger.Debug("Listing resource")
			err = retry.OnError(retry.DefaultBackoff, retriable, func() error {
				l, err := nri.List(ctx, opts)
				if err != nil {
					logger.Error("failed to list resource",
						"err", err,
					)
				} else {
					list = l
					latestResourceVersion = l.GetResourceVersion()
				}
				return err
			})
			return list, err
		})

		pagerConfig := s.saveConfig.PagerConfig

		if pagerConfig != nil {
			if pagerConfig.PageSize > 0 {
				listPager.PageSize = pagerConfig.PageSize
			}
			if pagerConfig.PageBufferSize > 0 {
				listPager.PageBufferSize = pagerConfig.PageBufferSize
			}
		}

		var track *TrackData
		if tracks != nil {
			track = tracks[rm]
			if track == nil {
				track = &TrackData{
					Data: map[log.ObjectRef]json.RawMessage{},
				}
				tracks[rm] = track
			}
		}
		count := 0
		if err := listPager.EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
			if o, ok := obj.(metav1.Object); ok {
				o.SetResourceVersion("")
				if track != nil {
					track.Data[log.KObj(o)], _ = json.Marshal(o)
				}
			}
			count++
			return encoder.Encode(obj)
		}); err != nil {
			return fmt.Errorf("failed to list resource %q: %w", gvr.Resource, err)
		}

		if track != nil {
			track.ResourceVersion = latestResourceVersion
		}
		logger.Debug("Listed resource",
			"counter", count,
			"elapsed", time.Since(start),
		)
		totalCounter += count
	}

	if tracks == nil {
		if totalCounter == 0 {
			return ErrNotHandled
		}
	}
	logger.Info("Saved resources",
		"counter", totalCounter,
		"elapsed", time.Since(startTime),
	)

	return nil
}

const (
	// recordReorderBuffer is the number of events kept buffered to tolerate
	// events that are out of order over a period of time.
	recordReorderBuffer = 1024
	// recordCheckpointInterval is the number of committed events between two
	// progress boundaries.
	recordCheckpointInterval = 128
	// recordMinCheckpointInterval throttles progress boundaries when the
	// recorder is only receiving a small number of events.
	recordMinCheckpointInterval = time.Second
)

// RecordConfig configures a recording session.
type RecordConfig struct {
	// Encoder writes the recording stream.
	Encoder *yaml.Encoder
	// Tracks contains the committed state and the last committed position
	// per resource kind.
	Tracks map[*meta.RESTMapping]*TrackData
	// StartTime is the base time used to compute the relative durations.
	// It defaults to the current time and must be set to the original
	// recording start time when resuming.
	StartTime time.Time
	// BoundaryFlusher is invoked after a progress boundary is written so
	// that buffered compression data can be flushed and the file synced.
	BoundaryFlusher func() error
}

// Record records the changes of the cluster.
//
// Every resource kind is watched independently. A disconnected watch is
// restarted from the last known position for that resource, and if the
// position has expired the resource is listed again and the net changes
// relative to the committed object state are recorded. Progress boundaries
// are written periodically so that the recording can be resumed after a
// process restart.
func (s *Saver) Record(ctx context.Context, encoder *yaml.Encoder, tracks map[*meta.RESTMapping]*TrackData) error {
	return s.RecordWithConfig(ctx, RecordConfig{
		Encoder: encoder,
		Tracks:  tracks,
	})
}

// RecordWithConfig records the changes of the cluster with explicit options.
func (s *Saver) RecordWithConfig(ctx context.Context, config RecordConfig) error {
	if len(config.Tracks) == 0 {
		return nil
	}
	startTime := config.StartTime
	if startTime.IsZero() {
		startTime = s.clock.Now()
	}

	rec := &recorder{
		saver:           s,
		encoder:         config.Encoder,
		startTime:       startTime,
		boundaryFlusher: config.BoundaryFlusher,
		ctx:             ctx,
		que:             queue.NewQueue[*resourcePatchEvent](),
		inflight:        map[schema.GroupVersionResource]int{},
		committed:       map[schema.GroupVersionResource]string{},
		written:         map[schema.GroupVersionResource]string{},
	}

	for rm, track := range config.Tracks {
		gvr := rm.Resource
		rec.committed[gvr] = track.ResourceVersion
		rec.written[gvr] = track.ResourceVersion
	}

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()

	var wg sync.WaitGroup
	for rm, track := range config.Tracks {
		gvr := rm.Resource
		patchMeta, err := s.patchMetaSchema.Lookup(gvr)
		if err != nil {
			return fmt.Errorf("failed to lookup patch meta: %w", err)
		}
		wg.Add(1)
		go func(rm *meta.RESTMapping, track *TrackData, patchMeta strategicpatch.LookupPatchMeta) {
			defer wg.Done()
			s.watchResource(watchCtx, rec, rm, track, patchMeta, startTime)
		}(rm, track, patchMeta)
	}

	workersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDone)
	}()

	return rec.run(ctx, workersDone)
}

// resourcePatchEvent is a patch that is produced by a resource watcher.
// resourceVersion is the position of the event for its resource kind; it is
// advanced to the committed position only after the patch is written.
// A nil patch is a watermark-only event used to advance the position after
// a resource resynchronization.
type resourcePatchEvent struct {
	gvr             schema.GroupVersionResource
	resourceVersion string
	at              time.Time
	patch           *recording.ResourcePatch
}

// recorder serializes the events of all resource watchers into a single
// ordered stream and maintains the committed positions.
type recorder struct {
	saver           *Saver
	encoder         *yaml.Encoder
	startTime       time.Time
	boundaryFlusher func() error
	ctx             context.Context

	que queue.Queue[*resourcePatchEvent]

	mu        sync.Mutex
	inflight  map[schema.GroupVersionResource]int
	committed map[schema.GroupVersionResource]string
	written   map[schema.GroupVersionResource]string
}

// enqueue adds an event produced by a resource watcher.
func (r *recorder) enqueue(event *resourcePatchEvent) {
	r.mu.Lock()
	r.inflight[event.gvr]++
	r.mu.Unlock()
	r.que.Add(event)
}

// finish marks an event as written and advances the committed position.
func (r *recorder) finish(event *resourcePatchEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inflight[event.gvr]--
	if event.resourceVersion != "" && resourceVersionGreater(event.resourceVersion, r.committed[event.gvr]) {
		r.committed[event.gvr] = event.resourceVersion
	}
}

// positionsToCommit returns the positions that can be committed in a progress
// boundary. A position is only returned once every queued event of the
// resource kind is written.
func (r *recorder) positionsToCommit(all bool) map[schema.GroupVersionResource]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	positions := map[schema.GroupVersionResource]string{}
	for gvr, resourceVersion := range r.committed {
		if resourceVersion == "" {
			continue
		}
		if !all && r.inflight[gvr] != 0 {
			continue
		}
		if resourceVersion == r.written[gvr] {
			continue
		}
		positions[gvr] = resourceVersion
	}
	return positions
}

func (r *recorder) markCommitted(positions map[schema.GroupVersionResource]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for gvr, resourceVersion := range positions {
		r.written[gvr] = resourceVersion
	}
}

// writeProgress writes a commit boundary and flushes it to stable storage.
func (r *recorder) writeProgress(all bool) {
	logger := log.FromContext(r.ctx)
	positions := r.positionsToCommit(all)
	if len(positions) == 0 {
		return
	}
	if err := r.encoder.Encode(recording.NewRecordingProgress(positions)); err != nil {
		logger.Warn("Failed to encode recording progress",
			"err", err,
		)
		return
	}
	if r.boundaryFlusher != nil {
		if err := r.boundaryFlusher(); err != nil {
			logger.Warn("Failed to flush recording progress",
				"err", err,
			)
		}
	}
	r.markCommitted(positions)
}

func (r *recorder) run(ctx context.Context, workersDone <-chan struct{}) error {
	logger := log.FromContext(ctx)

	h := heap.NewHeap[time.Duration, *resourcePatchEvent]()
	encodedSinceCheckpoint := 0
	lastCheckpoint := r.saver.clock.Now()

	handle := func(event *resourcePatchEvent) {
		if event.patch != nil {
			if err := r.encoder.Encode(event.patch); err != nil {
				logger.Warn("Failed to encode resource patch",
					"err", err,
				)
			}
			encodedSinceCheckpoint++
		}
		r.finish(event)
	}

	for {
		event, ok := r.que.GetOrWaitWithDone(workersDone)
		if ok {
			h.Push(event.at.Sub(r.startTime), event)
		}

		// Tolerate events that are out of order over a period of time.
		for h.Len() >= recordReorderBuffer {
			_, ev, _ := h.Pop()
			handle(ev)
		}

		if encodedSinceCheckpoint >= recordCheckpointInterval {
			r.writeProgress(false)
			encodedSinceCheckpoint = 0
			lastCheckpoint = r.saver.clock.Now()
		} else if ok && h.Len() == 0 && r.que.Len() == 0 &&
			r.saver.clock.Since(lastCheckpoint) >= recordMinCheckpointInterval {
			// Everything received so far is written; make it a boundary so
			// that an unexpected stop does not discard it.
			r.writeProgress(false)
			encodedSinceCheckpoint = 0
			lastCheckpoint = r.saver.clock.Now()
		}

		if !ok {
			// All watchers have stopped. Move every event that was already
			// queued into the heap so that the final timeline keeps the
			// original relative order, then flush everything and write a
			// final boundary.
			for {
				ev, getOK := r.que.Get()
				if !getOK {
					break
				}
				h.Push(ev.at.Sub(r.startTime), ev)
			}
			for {
				_, ev, popOK := h.Pop()
				if !popOK {
					break
				}
				handle(ev)
			}
			if ctx.Err() == nil {
				logger.Info("Recording stopped")
			}
			r.writeProgress(true)
			return nil
		}
	}
}

// watchResource keeps the watch of a single resource kind alive for the whole
// recording session. Failures of this watcher do not affect the watchers of
// the other resource kinds.
func (s *Saver) watchResource(ctx context.Context, rec *recorder, rm *meta.RESTMapping, track *TrackData, patchMeta strategicpatch.LookupPatchMeta, startTime time.Time) {
	gvr := rm.Resource
	nri := s.dynamicClient.Resource(gvr)
	logger := log.FromContext(ctx).With(
		"resource", gvr.Resource,
	)

	// The position used to (re)start the watch. It always covers every event
	// that has been received, so a reconnect never delivers an event twice
	// while the process is alive.
	rv := track.ResourceVersion
	backoff := newReconnectBackoff()

	for ctx.Err() == nil {
		w, err := nri.Watch(ctx, metav1.ListOptions{
			ResourceVersion:     rv,
			AllowWatchBookmarks: true,
		})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isResourceVersionExpired(err) {
				logger.Warn("Watch position expired, relisting resource",
					"resourceVersion", rv,
				)
				newRV, resyncErr := s.resyncResource(ctx, rec, rm, track, patchMeta, startTime, logger)
				if resyncErr != nil {
					if ctx.Err() != nil {
						return
					}
					logger.Warn("Failed to relist resource",
						"err", resyncErr,
					)
					if !sleepReconnectBackoff(ctx, &backoff) {
						return
					}
					continue
				}
				rv = newRV
				backoff = newReconnectBackoff()
				continue
			}
			logger.Warn("Failed to watch resource",
				"err", err,
			)
			if !sleepReconnectBackoff(ctx, &backoff) {
				return
			}
			continue
		}

		lastRV, expired := s.receiveWatchEvents(ctx, w, rec, gvr, track, patchMeta, startTime, rv, logger)
		w.Stop()
		rv = lastRV

		if ctx.Err() != nil {
			return
		}
		if expired {
			logger.Warn("Watch position expired, relisting resource",
				"resourceVersion", rv,
			)
			newRV, err := s.resyncResource(ctx, rec, rm, track, patchMeta, startTime, logger)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Warn("Failed to relist resource",
					"err", err,
				)
				if !sleepReconnectBackoff(ctx, &backoff) {
					return
				}
				continue
			}
			// The list just validated the new position, reconnect right away.
			rv = newRV
			backoff = newReconnectBackoff()
			continue
		}

		logger.Info("Watch closed, reconnecting",
			"resourceVersion", rv,
		)
		if !sleepReconnectBackoff(ctx, &backoff) {
			return
		}
	}
}

// receiveWatchEvents drains a watch until it closes, fails with an expired
// position, or the context is canceled. It returns the last known position
// and whether the position has expired.
func (s *Saver) receiveWatchEvents(
	ctx context.Context,
	w watch.Interface,
	rec *recorder,
	gvr schema.GroupVersionResource,
	track *TrackData,
	patchMeta strategicpatch.LookupPatchMeta,
	startTime time.Time,
	rv string,
	logger *log.Logger,
) (string, bool) {
	ch := w.ResultChan()
	for {
		select {
		case <-ctx.Done():
			return rv, false
		case event, ok := <-ch:
			if !ok {
				return rv, false
			}

			switch obj := event.Object.(type) {
			case *metav1.Status:
				if isExpiredStatus(obj) {
					return rv, true
				}
				if ctx.Err() != nil {
					return rv, false
				}
				logger.Warn("Watch error status",
					"reason", obj.Reason,
					"message", obj.Message,
				)
				return rv, false
			case metav1.Object:
				if event.Type == watch.Bookmark {
					if bookmarkRV := obj.GetResourceVersion(); bookmarkRV != "" && resourceVersionGreater(bookmarkRV, rv) {
						rv = bookmarkRV
					}
					continue
				}

				eventRV := obj.GetResourceVersion()
				patch, err := s.buildResourcePatch(event, patchMeta, gvr, s.clock.Now(), startTime, track.Data)
				if err != nil {
					logger.Warn("Failed to generate resource patch",
						"err", err,
					)
					continue
				}
				rec.enqueue(&resourcePatchEvent{
					gvr:             gvr,
					resourceVersion: eventRV,
					at:              s.clock.Now(),
					patch:           patch,
				})
				if eventRV != "" && resourceVersionGreater(eventRV, rv) {
					rv = eventRV
				}
			default:
				logger.Warn("Unknown watch object type",
					"type", fmt.Sprintf("%T", event.Object),
				)
			}
		}
	}
}

// resyncResource re-lists a resource kind after its watch position expired
// and records the net changes between the committed object state and the
// current cluster state. It returns the resource version of the list that
// can be used to restart the watch.
func (s *Saver) resyncResource(
	ctx context.Context,
	rec *recorder,
	rm *meta.RESTMapping,
	track *TrackData,
	patchMeta strategicpatch.LookupPatchMeta,
	startTime time.Time,
	logger *log.Logger,
) (string, error) {
	gvr := rm.Resource
	nri := s.dynamicClient.Resource(gvr)

	at := s.clock.Now()
	latestResourceVersion := track.ResourceVersion
	listPager := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		var list runtime.Object
		err := retry.OnError(retry.DefaultBackoff, retriable, func() error {
			l, err := nri.List(ctx, opts)
			if err == nil {
				list = l
				latestResourceVersion = l.GetResourceVersion()
			}
			return err
		})
		return list, err
	})

	if pagerConfig := s.saveConfig.PagerConfig; pagerConfig != nil {
		if pagerConfig.PageSize > 0 {
			listPager.PageSize = pagerConfig.PageSize
		}
		if pagerConfig.PageBufferSize > 0 {
			listPager.PageBufferSize = pagerConfig.PageBufferSize
		}
	}

	seen := map[log.ObjectRef]struct{}{}
	count := 0
	if err := listPager.EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		o, ok := obj.(metav1.Object)
		if !ok {
			return nil
		}
		key := log.KObj(o)
		seen[key] = struct{}{}
		o.SetResourceVersion("")

		patchObj := recording.ResourcePatch{TypeMeta: recording.ResourcePatchType}
		patchObj.SetTargetGroupVersionResource(gvr)
		patchObj.SetTargetName(key.Name, key.Namespace)
		patchObj.SetDuration(at.Sub(startTime))
		if err := patchObj.SetContent(o, track.Data, patchMeta); err != nil {
			return err
		}
		rec.enqueue(&resourcePatchEvent{
			gvr: gvr,
			at:  at,
			// The position is advanced by the watermark event below, once
			// every change of the resynchronization is written.
			patch: &patchObj,
		})
		count++
		return nil
	}); err != nil {
		return "", fmt.Errorf("failed to relist resource %q: %w", gvr.Resource, err)
	}

	// Objects that have been deleted since the last committed position are
	// missing from the list and are turned into delete patches.
	var stale []log.ObjectRef
	for key := range track.Data {
		if _, ok := seen[key]; !ok {
			stale = append(stale, key)
		}
	}
	for _, key := range stale {
		obj := &unstructured.Unstructured{}
		obj.SetName(key.Name)
		obj.SetNamespace(key.Namespace)

		patchObj := recording.ResourcePatch{TypeMeta: recording.ResourcePatchType}
		patchObj.SetTargetGroupVersionResource(gvr)
		patchObj.SetTargetName(key.Name, key.Namespace)
		patchObj.SetDuration(at.Sub(startTime))
		patchObj.SetDelete(obj, track.Data)
		rec.enqueue(&resourcePatchEvent{
			gvr:   gvr,
			at:    at,
			patch: &patchObj,
		})
		count++
	}

	// Advance the committed position to the list resource version only after
	// all the changes above are written.
	if latestResourceVersion != "" {
		rec.enqueue(&resourcePatchEvent{
			gvr:             gvr,
			resourceVersion: latestResourceVersion,
			at:              at.Add(time.Nanosecond),
			patch:           nil,
		})
	}

	logger.Info("Relisted resource after watch position expired",
		"counter", count,
		"resourceVersion", latestResourceVersion,
	)
	return latestResourceVersion, nil
}

func newReconnectBackoff() wait.Backoff {
	return wait.Backoff{
		Steps:    20,
		Duration: time.Second,
		Factor:   1.6,
		Jitter:   0.1,
		Cap:      30 * time.Second,
	}
}

func sleepReconnectBackoff(ctx context.Context, backoff *wait.Backoff) bool {
	timer := time.NewTimer(backoff.Step())
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func isResourceVersionExpired(err error) bool {
	if apierrors.IsGone(err) {
		return true
	}
	var statusErr *apierrors.StatusError
	if errors.As(err, &statusErr) {
		return statusErr.ErrStatus.Reason == metav1.StatusReasonExpired
	}
	return false
}

func isExpiredStatus(status *metav1.Status) bool {
	return status.Code == http.StatusGone || status.Reason == metav1.StatusReasonExpired
}

// resourceVersionGreater reports whether resource version a is greater than b.
func resourceVersionGreater(a, b string) bool {
	if a == "" {
		return false
	}
	if b == "" {
		return true
	}
	ai, errA := parseResourceVersion(a)
	bi, errB := parseResourceVersion(b)
	if errA == nil && errB == nil {
		return ai > bi
	}
	return a > b
}

func parseResourceVersion(resourceVersion string) (uint64, error) {
	return strconv.ParseUint(resourceVersion, 10, 64)
}

func retriable(err error) bool {
	return apierrors.IsInternalError(err) ||
		apierrors.IsServiceUnavailable(err) ||
		apierrors.IsTooManyRequests(err) ||
		apierrors.IsTimeout(err) ||
		apierrors.IsServerTimeout(err) ||
		net.IsConnectionRefused(err)
}

// TrackData holds tracking information for resources being recorded
// Data contains a map of object references to their raw JSON representations
// ResourceVersion tracks the last observed resource version for synchronization
type TrackData struct {
	Data            map[log.ObjectRef]json.RawMessage
	ResourceVersion string
}

func (s *Saver) buildResourcePatch(event watch.Event, patchMeta strategicpatch.LookupPatchMeta, gvr schema.GroupVersionResource, at, startTime time.Time, track map[log.ObjectRef]json.RawMessage) (*recording.ResourcePatch, error) {
	obj, ok := event.Object.(metav1.Object)
	if !ok {
		return nil, fmt.Errorf("unknown object type: %T", event.Object)
	}

	rp := recording.ResourcePatch{
		TypeMeta: recording.ResourcePatchType}
	rp.SetTargetGroupVersionResource(gvr)
	rp.SetTargetName(obj.GetName(), obj.GetNamespace())
	rp.SetDuration(at.Sub(startTime))

	switch event.Type {
	case watch.Added, watch.Modified:
		obj.SetResourceVersion("")

		err := rp.SetContent(obj, track, patchMeta)
		if err != nil {
			return nil, err
		}
		return &rp, nil
	case watch.Deleted:
		rp.SetDelete(obj, track)

		return &rp, nil
	default:
		return nil, fmt.Errorf("unknown event type: %s", event.Type)
	}
}
