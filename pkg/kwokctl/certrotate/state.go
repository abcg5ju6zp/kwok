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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Phase is a confirmed stage of a certificate rotation.
type Phase string

const (
	// PhasePreparing means the target generation has been journaled but its
	// isolated material is not fully prepared yet.
	PhasePreparing Phase = "Preparing"
	// PhasePrepared means the new material has been generated and validated in
	// isolation; the running cluster has not been touched yet.
	PhasePrepared Phase = "Prepared"
	// PhaseEtcdSwitched means etcd accepts the new generation.
	PhaseEtcdSwitched Phase = "EtcdSwitched"
	// PhaseApiserverSwitched means the API server serves the new generation.
	PhaseApiserverSwitched Phase = "ApiserverSwitched"
	// PhaseControllersSwitched means all in cluster controllers use the new generation.
	PhaseControllersSwitched Phase = "ControllersSwitched"
	// PhaseClientsSwitched means all in cluster client material (kubeconfig files)
	// has been switched to the new generation.
	PhaseClientsSwitched Phase = "ClientsSwitched"
	// PhaseKubeconfigPublished means the host kubeconfig has been published and
	// verified against the new generation.
	PhaseKubeconfigPublished Phase = "KubeconfigPublished"
)

// phaseOrder gives the order in which phases are confirmed.
var phaseOrder = map[Phase]int{
	PhasePreparing:           0,
	PhasePrepared:            1,
	PhaseEtcdSwitched:        2,
	PhaseApiserverSwitched:   3,
	PhaseControllersSwitched: 4,
	PhaseClientsSwitched:     5,
	PhaseKubeconfigPublished: 6,
}

func (p Phase) reached(other Phase) bool {
	return phaseOrder[p] >= phaseOrder[other]
}

// State is the on-disk journal of a single rotation. It is the only piece of
// state a restarted process needs to continue a rotation from the last
// confirmed stage.
type State struct {
	// Generation is the identifiable target generation of this rotation.
	Generation string `json:"generation"`
	// Phase is the last confirmed stage.
	Phase Phase `json:"phase"`
	// StartedAt records when the rotation started.
	StartedAt time.Time `json:"startedAt"`
	// UpdatedAt records when the journal was last written.
	UpdatedAt time.Time `json:"updatedAt"`
	// SwitchedComponents records the components that have already accepted the
	// new generation, in switch order.
	SwitchedComponents []string `json:"switchedComponents,omitempty"`
	// SANs is the informational snapshot of SANs used to build the generation.
	SANs []string `json:"sans,omitempty"`
}

func newState(now time.Time) (*State, error) {
	id, err := newGenerationID(now)
	if err != nil {
		return nil, err
	}
	return &State{
		Generation: id,
		Phase:      PhasePreparing,
		StartedAt:  now.UTC(),
		UpdatedAt:  now.UTC(),
	}, nil
}

// newGenerationID returns an identifiable, unique generation name. It is
// sortable by creation time and carries a random suffix so that concurrent
// rotations never collide.
func newGenerationID(now time.Time) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to generate generation id: %w", err)
	}
	return fmt.Sprintf("gen-%s-%x", now.UTC().Format("20060102-150405"), b[:]), nil
}

const (
	rotationDirName       = "rotation"
	stateFileName         = "state.json"
	newMaterialDirName    = "new"
	oldMaterialDirName    = "old"
	clientsBackupDirName  = "clients-backup"
	kubeconfigBackupName  = "kubeconfig-backup"
	nodeBackupDirName     = "node"
	componentConfFilePerm = 0600
)

func rotationRoot(pkiDir string) string {
	return filepath.Join(pkiDir, rotationDirName)
}

func statePath(pkiDir string) string {
	return filepath.Join(rotationRoot(pkiDir), stateFileName)
}

// Generation describes the on-disk locations of one rotation generation.
type Generation struct {
	// ID is the target generation identifier.
	ID string
	// Root is the isolated directory owned by the generation.
	Root string
	// LiveDir is the directory from which components read their material.
	LiveDir string
	// NewDir contains the material of the target generation.
	NewDir string
	// OldDir keeps the material of the generation that is being replaced, until
	// the new chain has been fully verified.
	OldDir string
}

func generationOf(pkiDir string, id string) Generation {
	root := filepath.Join(rotationRoot(pkiDir), id)
	return Generation{
		ID:      id,
		Root:    root,
		LiveDir: pkiDir,
		NewDir:  filepath.Join(root, newMaterialDirName),
		OldDir:  filepath.Join(root, oldMaterialDirName),
	}
}

// ClientsBackupDir is where runtime hooks keep the previous in cluster client
// files before publishing new ones.
func (g Generation) ClientsBackupDir() string {
	return filepath.Join(g.Root, clientsBackupDirName)
}

// KubeconfigBackupDir is where runtime hooks keep the previous host kubeconfig
// files before publishing new ones.
func (g Generation) KubeconfigBackupDir() string {
	return filepath.Join(g.Root, kubeconfigBackupName)
}

// NodeBackupDir keeps runtime specific files that have to be copied back to a
// node on rollback.
func (g Generation) NodeBackupDir() string {
	return filepath.Join(g.OldDir, nodeBackupDirName)
}

func loadState(pkiDir string) (*State, error) {
	data, err := os.ReadFile(statePath(pkiDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read rotation journal %s: %w", statePath(pkiDir), err)
	}
	state := &State{}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("failed to parse rotation journal %s: %w", statePath(pkiDir), err)
	}
	if state.Generation == "" {
		return nil, fmt.Errorf("rotation journal %s does not record a generation", statePath(pkiDir))
	}
	return state, nil
}

func saveState(pkiDir string, state *State) error {
	state.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode rotation journal: %w", err)
	}
	if err := writeFileAtomic(statePath(pkiDir), append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write rotation journal: %w", err)
	}
	return nil
}
