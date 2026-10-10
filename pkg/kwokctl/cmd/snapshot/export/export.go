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

// Package export is the export of external cluster
package export

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/kwok/pkg/kwokctl/dryrun"
	"sigs.k8s.io/kwok/pkg/kwokctl/recording"
	"sigs.k8s.io/kwok/pkg/kwokctl/snapshot"
	"sigs.k8s.io/kwok/pkg/log"
	"sigs.k8s.io/kwok/pkg/utils/client"
	"sigs.k8s.io/kwok/pkg/utils/completion"
	"sigs.k8s.io/kwok/pkg/utils/file"
	"sigs.k8s.io/kwok/pkg/utils/kubeconfig"
	"sigs.k8s.io/kwok/pkg/utils/yaml"
)

type flagpole struct {
	Path              string
	Kubeconfig        string
	Filters           []string
	ImpersonateUser   string
	ImpersonateGroups []string
	PageSize          int64
	PageBufferSize    int32
	Record            bool
	Resume            bool
}

// NewCommand returns a new cobra.Command for cluster exporting.
func NewCommand(ctx context.Context) *cobra.Command {
	flags := &flagpole{
		PageSize:       500,
		PageBufferSize: 10,
		Filters:        snapshot.Resources,
	}

	cmd := &cobra.Command{
		Args:              cobra.NoArgs,
		Use:               "export",
		Short:             "[experimental] Export the snapshots of external clusters",
		ValidArgsFunction: completion.NoFileCompletions,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd.Context(), flags)
		},
	}
	cmd.Flags().StringVar(&flags.Kubeconfig, "kubeconfig", flags.Kubeconfig, "Path to the kubeconfig file to use")
	_ = cmd.RegisterFlagCompletionFunc("kubeconfig", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		defaultKubeconfig := kubeconfig.GetRecommendedKubeconfigPath()
		if strings.HasPrefix(defaultKubeconfig, toComplete) {
			return []string{defaultKubeconfig}, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveDefault
	})
	cmd.Flags().StringVar(&flags.Path, "path", flags.Path, "Path to the snapshot")
	cmd.Flags().StringSliceVar(&flags.Filters, "filter", flags.Filters, "Filter the resources to export")
	_ = cmd.RegisterFlagCompletionFunc("filter", completion.FixedCompletions(snapshot.Resources))
	cmd.Flags().StringVar(&flags.ImpersonateUser, "as", flags.ImpersonateUser, "Username to impersonate for the operation. User could be a regular user or a service account in a namespace.")
	cmd.Flags().StringSliceVar(&flags.ImpersonateGroups, "as-group", flags.ImpersonateGroups, "Group to impersonate for the operation, this flag can be repeated to specify multiple groups.")
	cmd.Flags().Int64Var(&flags.PageSize, "page-size", flags.PageSize, "Define the page size")
	cmd.Flags().Int32Var(&flags.PageBufferSize, "page-buffer-size", flags.PageBufferSize, "Define the number of pages to buffer")
	cmd.Flags().BoolVar(&flags.Record, "record", flags.Record, "Record the change of the cluster")
	cmd.Flags().BoolVar(&flags.Resume, "resume", flags.Resume, "Resume recording into an existing recording file; the filter scope must match the original recording")
	return cmd
}

func runE(ctx context.Context, flags *flagpole) error {
	if flags.Path == "" {
		return fmt.Errorf("path is required")
	}
	if flags.Resume && !flags.Record {
		return fmt.Errorf("--resume can only be used with --record")
	}
	if flags.Resume {
		if !file.Exists(flags.Path) {
			return fmt.Errorf("file %q does not exist", flags.Path)
		}
	} else if file.Exists(flags.Path) {
		return fmt.Errorf("file %q already exists", flags.Path)
	}

	if dryrun.DryRun {
		if flags.Resume {
			dryrun.PrintMessagef("resume recording to %s with filters %s", flags.Path, strings.Join(flags.Filters, ","))
		} else {
			dryrun.PrintMessagef("kubectl --kubeconfig %s get %s -o yaml >%s", flags.Kubeconfig, strings.Join(flags.Filters, ","), flags.Path)
		}
		return nil
	}

	clientset, err := client.NewClientset("", flags.Kubeconfig,
		client.WithImpersonate(rest.ImpersonationConfig{
			UserName: flags.ImpersonateUser,
			Groups:   flags.ImpersonateGroups,
		}),
	)
	if err != nil {
		return err
	}

	logger := log.FromContext(ctx)

	pagerConfig := &snapshot.PagerConfig{
		PageSize:       flags.PageSize,
		PageBufferSize: flags.PageBufferSize,
	}

	restMapper, err := clientset.ToRESTMapper()
	if err != nil {
		return err
	}

	filters, errs := client.MappingForResources(restMapper, flags.Filters)
	if len(errs) > 0 {
		for _, err := range errs {
			logger.Error("failed to get mapping",
				"err", err,
			)
		}
	}

	saver, err := snapshot.NewSaver(snapshot.SaveConfig{
		Clientset:   clientset,
		PagerConfig: pagerConfig,
		Filters:     filters,
	})
	if err != nil {
		return err
	}

	if !flags.Record {
		return exportOnce(ctx, flags, saver)
	}

	if flags.Resume {
		return resumeRecording(ctx, flags, saver, filters, logger)
	}

	return startRecording(ctx, flags, saver, filters, logger)
}

// exportOnce performs a one-shot export, without recording metadata or
// progress boundaries. The produced file is identical to the files written
// by previous versions.
func exportOnce(ctx context.Context, flags *flagpole, saver *snapshot.Saver) error {
	f, err := file.Open(flags.Path)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	press := file.Compress(flags.Path, f)
	defer func() {
		_ = press.Close()
	}()

	var writer io.Writer = press

	startTime := time.Now()
	writer = recording.NewWriteHook(writer, func(b []byte) []byte {
		return recording.ReplaceTimeToRelative(startTime, b)
	})

	encoder := yaml.NewEncoder(writer)

	return saver.Save(ctx, encoder, nil)
}

// recordingWriter is the open output of a recording file.
type recordingWriter struct {
	file    *os.File
	press   io.WriteCloser
	encoder *yaml.Encoder
}

// flush makes every document written so far durable.
func (w *recordingWriter) flush() error {
	// Flush the compression stream before syncing the underlying file.
	if gz, ok := w.press.(*gzip.Writer); ok {
		if err := gz.Flush(); err != nil {
			return err
		}
	}
	return w.file.Sync()
}

func (w *recordingWriter) close() {
	_ = w.press.Close()
	_ = w.file.Close()
}

// openRecordingWriter creates a new recording file for writing.
func openRecordingWriter(path string, startTime time.Time) (*recordingWriter, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}

	var press io.WriteCloser
	var writer io.Writer = f
	switch filepath.Ext(path) {
	case ".gz", ".tgz":
		gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		press = gz
		writer = gz
	default:
		press = nopWriteCloser{Writer: f}
	}

	writer = recording.NewWriteHook(writer, func(b []byte) []byte {
		return recording.ReplaceTimeToRelative(startTime, b)
	})

	return &recordingWriter{
		file:    f,
		press:   press,
		encoder: yaml.NewEncoder(writer),
	}, nil
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func startRecording(ctx context.Context, flags *flagpole, saver *snapshot.Saver, filters []*meta.RESTMapping, logger *log.Logger) error {
	startTime := time.Now()

	writer, err := openRecordingWriter(flags.Path, startTime)
	if err != nil {
		return err
	}
	defer writer.close()

	// The head document persists the filter scope and the base time, so the
	// recording can be validated and resumed later.
	filterGVRs := make([]schema.GroupVersionResource, 0, len(filters))
	for _, rm := range filters {
		filterGVRs = append(filterGVRs, rm.Resource)
	}
	if err := writer.encoder.Encode(recording.NewRecording(filterGVRs, startTime)); err != nil {
		return err
	}

	tracks := make(map[*meta.RESTMapping]*snapshot.TrackData)
	if err := saver.Save(ctx, writer.encoder, tracks); err != nil {
		return err
	}

	// Commit the initial state as the first complete boundary.
	positions := make(map[schema.GroupVersionResource]string, len(tracks))
	for rm, track := range tracks {
		positions[rm.Resource] = track.ResourceVersion
	}
	if err := writer.encoder.Encode(recording.NewRecordingProgress(positions)); err != nil {
		return err
	}
	if err := writer.flush(); err != nil {
		return err
	}

	logger.Info("Recording")
	logger.Info("Press Ctrl+C to stop recording resources")

	return saver.RecordWithConfig(ctx, snapshot.RecordConfig{
		Encoder:         writer.encoder,
		Tracks:          tracks,
		StartTime:       startTime,
		BoundaryFlusher: writer.flush,
	})
}

func resumeRecording(ctx context.Context, flags *flagpole, saver *snapshot.Saver, filters []*meta.RESTMapping, logger *log.Logger) error {
	resumeData, err := scanRecording(flags.Path)
	if err != nil {
		return err
	}

	result, err := saver.PrepareResume(ctx, resumeData, filters)
	if err != nil {
		return err
	}

	// Rewrite the file with only the complete prefix, so the new session
	// appends right after the last complete boundary.
	writer, err := rewriteRecordingPrefix(flags.Path, result.StartTime, resumeData.Documents)
	if err != nil {
		return err
	}
	defer writer.close()

	logger.Info("Resuming recording")
	logger.Info("Press Ctrl+C to stop recording resources")

	return saver.RecordWithConfig(ctx, snapshot.RecordConfig{
		Encoder:         writer.encoder,
		Tracks:          result.Tracks,
		StartTime:       result.StartTime,
		BoundaryFlusher: writer.flush,
	})
}

func scanRecording(path string) (*recording.ResumeData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	reader, err := file.Decompress(path, f)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = reader.Close()
	}()

	return recording.ReadResumeData(reader)
}

// rewriteRecordingPrefix writes the complete documents of a recording into a
// new file and atomically replaces the target, dropping the incomplete tail.
// The returned writer is already open on the target path and can be used to
// append the rest of the recording.
func rewriteRecordingPrefix(path string, startTime time.Time, documents []*unstructured.Unstructured) (*recordingWriter, error) {
	tmpPath := path + ".tmp"
	_ = os.Remove(tmpPath)

	writer, err := openRecordingWriter(tmpPath, startTime)
	if err != nil {
		return nil, err
	}

	for _, document := range documents {
		if err := writer.encoder.Encode(document); err != nil {
			writer.close()
			_ = os.Remove(tmpPath)
			return nil, err
		}
	}
	if err := writer.flush(); err != nil {
		writer.close()
		_ = os.Remove(tmpPath)
		return nil, err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		writer.close()
		_ = os.Remove(tmpPath)
		return nil, err
	}

	return writer, nil
}
