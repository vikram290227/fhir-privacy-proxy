package policyversion

import (
	"os"
	"path/filepath"
	"testing"
)

// helper: set up a temp policies root with a versions subdir holding
// the requested version names.
func writeVersions(t *testing.T, names ...string) string {
	t.Helper()
	root := t.TempDir()
	versionsDir := filepath.Join(root, "versions")
	for _, name := range names {
		dir := filepath.Join(versionsDir, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "authz.rego"), []byte("package authz"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestManager_List(t *testing.T) {
	root := writeVersions(t, "v1", "v2", "v3")
	m, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.List()
	if len(got) != 3 {
		t.Fatalf("expected 3 bundles, got %d", len(got))
	}
	if got[0].Version != "v1" || got[2].Version != "v3" {
		t.Errorf("unexpected order: %+v", got)
	}
}

func TestManager_ActiveDefaultsToNewest(t *testing.T) {
	root := writeVersions(t, "v1", "v2", "v3")
	m, _ := New(root)
	if m.Active() != "v3" {
		t.Errorf("expected v3 active, got %q", m.Active())
	}
}

func TestManager_ActivateAndRollback(t *testing.T) {
	root := writeVersions(t, "v1", "v2", "v3")
	m, _ := New(root)

	if err := m.Activate("v2"); err != nil {
		t.Fatalf("Activate v2: %v", err)
	}
	if m.Active() != "v2" {
		t.Errorf("expected v2 active, got %q", m.Active())
	}

	if err := m.Activate("v1"); err != nil {
		t.Fatalf("Activate v1: %v", err)
	}

	prev, err := m.Rollback()
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if prev != "v2" || m.Active() != "v2" {
		t.Errorf("expected rollback to v2, got %q", prev)
	}

	prev, err = m.Rollback()
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if prev != "v3" || m.Active() != "v3" {
		t.Errorf("expected rollback to v3, got %q", prev)
	}

	if _, err := m.Rollback(); err == nil {
		t.Error("expected error when rollback stack is empty")
	}
}

func TestManager_UnknownVersion(t *testing.T) {
	root := writeVersions(t, "v1")
	m, _ := New(root)
	if err := m.Activate("v99"); err == nil {
		t.Error("expected error for unknown version")
	}
}

func TestManager_MissingDirectory(t *testing.T) {
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("expected nil error on missing dir, got %v", err)
	}
	if len(m.List()) != 0 {
		t.Error("expected empty bundle list")
	}
	if m.Active() != "" {
		t.Error("expected empty active version")
	}
}

func TestManager_ActivePath(t *testing.T) {
	root := writeVersions(t, "v1", "v2")
	m, _ := New(root)
	path := m.ActivePath()
	if path == "" {
		t.Fatal("expected active path")
	}
	if filepath.Base(path) != "v2" {
		t.Errorf("expected path to end in v2, got %s", path)
	}
}
