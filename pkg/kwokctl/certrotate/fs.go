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
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// writeFileAtomic writes data to path by writing a temporary file in the same
// directory and renaming it into place, so readers never observe a partial
// file.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func copyFileAtomic(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	if err := writeFileAtomic(dst, data); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}

// copyTree copies every regular file under srcRoot into dstRoot, preserving
// relative paths. Directories from skip are not copied. It returns the copied
// relative paths.
func copyTree(srcRoot, dstRoot string, skip map[string]struct{}) ([]string, error) {
	var copied []string
	err := filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == srcRoot {
			return nil
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if _, ok := skip[rel]; ok {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// Do not follow symlinks when backing up trust material.
			return nil
		}
		if _, ok := skip[rel]; ok {
			return nil
		}
		if err := copyFileAtomic(path, filepath.Join(dstRoot, rel)); err != nil {
			return err
		}
		copied = append(copied, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return copied, nil
}

// backupLiveMaterial snapshots every file of the live PKI directory into
// oldDir. The rotation working area itself is never backed up.
func backupLiveMaterial(liveDir, oldDir string) ([]string, error) {
	if err := os.MkdirAll(oldDir, 0o755); err != nil {
		return nil, err
	}
	return copyTree(liveDir, oldDir, map[string]struct{}{rotationDirName: {}})
}

// publishMaterial publishes the given relative files of the isolated new
// generation into the live PKI directory.
func publishMaterial(newDir, liveDir string, files []string) error {
	for _, rel := range files {
		src := filepath.Join(newDir, rel)
		if _, err := os.Stat(src); err != nil {
			return fmt.Errorf("new generation is missing %s: %w", rel, err)
		}
		if err := copyFileAtomic(src, filepath.Join(liveDir, rel)); err != nil {
			return fmt.Errorf("failed to publish %s: %w", rel, err)
		}
	}
	return nil
}

// restoreMaterial restores every backed up file from oldDir back into the live
// PKI directory.
func restoreMaterial(oldDir, liveDir string) error {
	if _, err := os.Stat(oldDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	_, err := copyTree(oldDir, liveDir, map[string]struct{}{nodeBackupDirName: {}})
	return err
}

// fileBackupRecord records where a backed up file must be restored to.
type fileBackupRecord struct {
	Source string `json:"source"`
	Name   string `json:"name"`
}

// BackupFiles copies the given files into backupDir and records their original
// locations so that RestoreFiles can put them back. Files that do not exist
// are recorded as absent and skipped on restore.
func BackupFiles(backupDir string, paths []string) error {
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return err
	}
	records := make([]fileBackupRecord, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		name := filepath.Base(path)
		record := fileBackupRecord{Source: path, Name: name}
		if _, err := os.Stat(path); err == nil {
			if err := copyFileAtomic(path, filepath.Join(backupDir, name)); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		records = append(records, record)
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(backupDir, "files.json"), append(data, '\n'))
}

// RestoreFiles restores files previously saved by BackupFiles.
func RestoreFiles(backupDir string) error {
	data, err := os.ReadFile(filepath.Join(backupDir, "files.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var records []fileBackupRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	for _, record := range records {
		backup := filepath.Join(backupDir, record.Name)
		if _, err := os.Stat(backup); err != nil {
			if os.IsNotExist(err) {
				// The file did not exist before publishing; remove the new one.
				if err := os.Remove(record.Source); err != nil && !os.IsNotExist(err) {
					return err
				}
				continue
			}
			return err
		}
		if err := copyFileAtomic(backup, record.Source); err != nil {
			return err
		}
	}
	return nil
}
