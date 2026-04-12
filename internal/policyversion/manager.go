// Package policyversion manages OPA policy bundle versions and
// supports atomic rollback to any previous version.
//
// Policies live on disk under a versioned directory layout:
//
//	policies/
//	  base/                   # current symlink target (legacy)
//	  versions/
//	    v1/authz.rego
//	    v2/authz.rego
//	    v3/authz.rego
//
// The manager keeps an in-memory ordered list of versions and tracks
// which one is "active". Rollback simply updates the pointer and
// reloads the bundle into OPA via the admin API (out of scope here;
// this package focuses on discovery, listing, and selection).
package policyversion

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Bundle describes a single policy version on disk.
type Bundle struct {
	Version string // e.g. "v1", "v2"
	Path    string // directory path on disk
}

// Manager owns the set of known bundles and the active pointer.
type Manager struct {
	root     string
	bundles  []Bundle
	active   string
	history  []string // stack of previous active versions for rollback
	mu       sync.RWMutex
}

// New scans root/versions/* for bundles and marks the highest numeric
// version as active. Returns an empty manager if the directory does
// not exist (policies may still be hot-loaded later).
func New(root string) (*Manager, error) {
	m := &Manager{root: root}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

// Reload re-scans the versions directory. Safe to call at runtime;
// the active pointer is preserved if the current version is still on
// disk, otherwise it's reset to the newest version discovered.
func (m *Manager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	versionsDir := filepath.Join(m.root, "versions")
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			m.bundles = nil
			return nil
		}
		return fmt.Errorf("policyversion: read %s: %w", versionsDir, err)
	}

	var bundles []Bundle
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		bundles = append(bundles, Bundle{
			Version: e.Name(),
			Path:    filepath.Join(versionsDir, e.Name()),
		})
	}
	sort.Slice(bundles, func(i, j int) bool {
		return bundles[i].Version < bundles[j].Version
	})
	m.bundles = bundles

	// Preserve the active pointer if it still exists; otherwise take
	// the newest bundle.
	if m.active != "" {
		for _, b := range bundles {
			if b.Version == m.active {
				return nil
			}
		}
	}
	if len(bundles) > 0 {
		m.active = bundles[len(bundles)-1].Version
	}
	return nil
}

// List returns all known bundles in ascending version order.
func (m *Manager) List() []Bundle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Bundle, len(m.bundles))
	copy(out, m.bundles)
	return out
}

// Active returns the version currently selected for evaluation.
func (m *Manager) Active() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
}

// Activate switches the active pointer to version. The previous
// active version is pushed onto the history stack so Rollback can
// walk back one step at a time.
func (m *Manager) Activate(version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, b := range m.bundles {
		if b.Version == version {
			if m.active != "" && m.active != version {
				m.history = append(m.history, m.active)
			}
			m.active = version
			return nil
		}
	}
	return fmt.Errorf("policyversion: unknown version %q", version)
}

// Rollback restores the previous active version. It pops one entry
// off the history stack; calling Rollback repeatedly walks the entire
// history in LIFO order.
func (m *Manager) Rollback() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.history) == 0 {
		return "", fmt.Errorf("policyversion: no previous version to roll back to")
	}
	prev := m.history[len(m.history)-1]
	m.history = m.history[:len(m.history)-1]
	m.active = prev
	return prev, nil
}

// ActivePath returns the absolute path for the active bundle. An
// empty string is returned when no bundles are loaded.
func (m *Manager) ActivePath() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == "" {
		return ""
	}
	for _, b := range m.bundles {
		if b.Version == m.active {
			return b.Path
		}
	}
	return ""
}
