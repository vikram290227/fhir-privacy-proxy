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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// OPAAdmin is the narrow interface the version manager needs to push a
// bundle into OPA. It is satisfied by *policy.OPAAdmin. Defined here to
// keep policyversion free of the policy package import cycle and to let
// tests inject a mock.
type OPAAdmin interface {
	PutPolicy(ctx context.Context, id string, rego []byte) error
	DeletePolicy(ctx context.Context, id string) error
}

// opaPolicyID is the OPA policy id the manager uses when uploading the
// active authz.rego. Using a fixed id means every Activate/Rollback
// replaces the same module — OPA's PUT is idempotent by id, so the
// bundle OPA is running always matches the active pointer.
const opaPolicyID = "authz"

// opaPushTimeout bounds the upload RPC so a stuck OPA doesn't deadlock
// an Activate/Rollback call.
const opaPushTimeout = 10 * time.Second

// Bundle describes a single policy version on disk.
type Bundle struct {
	Version string // e.g. "v1", "v2"
	Path    string // directory path on disk
}

// Manager owns the set of known bundles and the active pointer.
type Manager struct {
	root    string
	bundles []Bundle
	active  string
	history []string // stack of previous active versions for rollback
	admin   OPAAdmin
	mu      sync.RWMutex
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

// SetOPAAdmin wires the OPA admin client the manager should use to
// push the active bundle on Activate / Rollback. Passing nil makes
// Activate/Rollback update only the in-memory pointer (useful for
// tests and for dry-run tooling).
func (m *Manager) SetOPAAdmin(admin OPAAdmin) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.admin = admin
}

// Activate switches the active pointer to version AND uploads the
// corresponding authz.rego to OPA. If the upload fails the in-memory
// pointer is not changed, so the manager's view stays consistent with
// the bundle OPA is actually running. The previous active version is
// pushed onto the history stack only after a successful upload so
// Rollback can walk back one step at a time.
func (m *Manager) Activate(version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activateLocked(version, true)
}

// Rollback restores the previous active version AND uploads its
// authz.rego to OPA. If the OPA upload fails the in-memory pointer
// stays on the current version and the history stack is untouched, so
// the caller can retry safely. Calling Rollback repeatedly walks the
// entire history in LIFO order.
func (m *Manager) Rollback() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.history) == 0 {
		return "", fmt.Errorf("policyversion: no previous version to roll back to")
	}
	prev := m.history[len(m.history)-1]

	// Peel the history entry off before calling activateLocked so the
	// swap isn't recorded as a new forward step. Restore it on error.
	m.history = m.history[:len(m.history)-1]
	if err := m.activateLocked(prev, false); err != nil {
		m.history = append(m.history, prev)
		return "", err
	}
	return prev, nil
}

// activateLocked is the shared core of Activate and Rollback. Caller
// must hold m.mu for writing. When pushHistory is true the current
// active version is pushed onto the stack before the swap (Activate
// semantics). When false (Rollback) the caller is responsible for
// having already managed the history stack.
//
// The order of operations matters for crash-safety:
//
//  1. Locate the target bundle and its authz.rego.
//  2. Call OPA PutPolicy. If this fails, nothing else changes.
//  3. Only after a 2xx from OPA do we flip m.active and push history.
//
// This guarantees that the in-memory pointer never disagrees with
// what OPA is actually serving.
func (m *Manager) activateLocked(version string, pushHistory bool) error {
	var target *Bundle
	for i := range m.bundles {
		if m.bundles[i].Version == version {
			target = &m.bundles[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("policyversion: unknown version %q", version)
	}

	// No-op when the caller re-activates the same version, but we still
	// push the Rego to OPA so an externally-edited OPA store is forced
	// back into the version the manager considers active.
	if m.admin != nil {
		regoPath := filepath.Join(target.Path, "authz.rego")
		rego, err := os.ReadFile(regoPath)
		if err != nil {
			return fmt.Errorf("policyversion: read %s: %w", regoPath, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), opaPushTimeout)
		defer cancel()
		if err := m.admin.PutPolicy(ctx, opaPolicyID, rego); err != nil {
			return fmt.Errorf("policyversion: opa upload %s: %w", version, err)
		}
	}

	if pushHistory && m.active != "" && m.active != version {
		m.history = append(m.history, m.active)
	}
	m.active = version
	return nil
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
