package policyversion

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/policy"
)

// ---------------------------------------------------------------------
// Mock OPA — a minimal in-memory key-value store behind the subset of
// the OPA policy API that the manager exercises: PUT and DELETE on
// /v1/policies/{id}.
// ---------------------------------------------------------------------

type mockOPAServer struct {
	mu       sync.Mutex
	policies map[string][]byte
	// failNextPut, if set, causes the next PUT to return HTTP 500
	// before the policy is stored. Reset to false after firing.
	failNextPut bool
	// putCount counts successful PUTs (useful for asserting that
	// Activate/Rollback actually push, not just flip a pointer).
	putCount int
}

func newMockOPAServer() (*httptest.Server, *mockOPAServer) {
	state := &mockOPAServer{policies: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/policies/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/policies/")
		state.mu.Lock()
		defer state.mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			if state.failNextPut {
				state.failNextPut = false
				http.Error(w, "simulated failure", http.StatusInternalServerError)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			state.policies[id] = body
			state.putCount++
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			if _, ok := state.policies[id]; !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			delete(state.policies, id)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, ok := state.policies[id]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return httptest.NewServer(mux), state
}

// writeVersionsWithContent sets up a policies root with named versions,
// each containing a distinct authz.rego payload so tests can assert
// that the *right* file landed in OPA.
func writeVersionsWithContent(t *testing.T, root string, bodies map[string]string) {
	t.Helper()
	versionsDir := filepath.Join(root, "versions")
	for name, body := range bodies {
		dir := filepath.Join(versionsDir, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "authz.rego"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------
// Happy path: Activate writes the target version's authz.rego to OPA.
// ---------------------------------------------------------------------
func TestActivate_UploadsBundleToOPA(t *testing.T) {
	root := t.TempDir()
	writeVersionsWithContent(t, root, map[string]string{
		"v1": "package authz\n# v1 bundle\n",
		"v2": "package authz\n# v2 bundle\n",
	})

	srv, state := newMockOPAServer()
	defer srv.Close()

	admin := policy.NewOPAAdmin(srv.URL, zap.NewNop())
	m, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.SetOPAAdmin(admin)

	if err := m.Activate("v1"); err != nil {
		t.Fatalf("Activate v1: %v", err)
	}

	state.mu.Lock()
	got := string(state.policies["authz"])
	state.mu.Unlock()
	if !strings.Contains(got, "v1 bundle") {
		t.Fatalf("OPA did not receive v1 rego: %q", got)
	}
	if m.Active() != "v1" {
		t.Fatalf("Active(): got %q want v1", m.Active())
	}
}

// ---------------------------------------------------------------------
// Rollback re-uploads the previous version's authz.rego, not just the
// in-memory pointer.
// ---------------------------------------------------------------------
func TestRollback_UploadsPreviousVersion(t *testing.T) {
	root := t.TempDir()
	writeVersionsWithContent(t, root, map[string]string{
		"v1": "package authz\n# v1 bundle\n",
		"v2": "package authz\n# v2 bundle\n",
		"v3": "package authz\n# v3 bundle\n",
	})

	srv, state := newMockOPAServer()
	defer srv.Close()

	admin := policy.NewOPAAdmin(srv.URL, zap.NewNop())
	m, _ := New(root)
	m.SetOPAAdmin(admin)

	// Step forward: v3 (default newest) → v1 → v2
	if err := m.Activate("v1"); err != nil {
		t.Fatalf("Activate v1: %v", err)
	}
	if err := m.Activate("v2"); err != nil {
		t.Fatalf("Activate v2: %v", err)
	}

	// Rollback should restore v1.
	prev, err := m.Rollback()
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if prev != "v1" {
		t.Fatalf("Rollback returned %q want v1", prev)
	}

	state.mu.Lock()
	got := string(state.policies["authz"])
	putCount := state.putCount
	state.mu.Unlock()
	if !strings.Contains(got, "v1 bundle") {
		t.Fatalf("OPA did not receive v1 rego after rollback: %q", got)
	}
	// 2 Activates + 1 Rollback => 3 uploads
	if putCount != 3 {
		t.Fatalf("expected 3 OPA PUTs, got %d", putCount)
	}
}

// ---------------------------------------------------------------------
// Failure: OPA rejects the PUT. The in-memory pointer must stay put so
// the manager's view of "active" stays in sync with OPA's actual bundle.
// ---------------------------------------------------------------------
func TestActivate_RevertsPointerOnOPAFailure(t *testing.T) {
	root := t.TempDir()
	writeVersionsWithContent(t, root, map[string]string{
		"v1": "package authz\n# v1 bundle\n",
		"v2": "package authz\n# v2 bundle\n",
	})

	srv, state := newMockOPAServer()
	defer srv.Close()

	admin := policy.NewOPAAdmin(srv.URL, zap.NewNop())
	m, _ := New(root)
	m.SetOPAAdmin(admin)

	// Pin OPA and the manager to v1 first.
	if err := m.Activate("v1"); err != nil {
		t.Fatalf("Activate v1: %v", err)
	}
	if m.Active() != "v1" {
		t.Fatalf("setup: Active()=%q want v1", m.Active())
	}

	// Arm a simulated OPA outage; the next PUT will fail.
	state.mu.Lock()
	state.failNextPut = true
	state.mu.Unlock()

	err := m.Activate("v2")
	if err == nil {
		t.Fatalf("expected error on failed OPA PUT, got nil")
	}
	// Pointer must still reflect v1 — anything else breaks the
	// invariant that Manager.Active() matches what OPA is serving.
	if m.Active() != "v1" {
		t.Fatalf("Active() after failure: got %q want v1 (pointer must NOT advance)", m.Active())
	}

	// History must not record the failed forward step either, or a
	// later Rollback would try to go "back" to v1 when we never left.
	// Attempting rollback should now succeed... only if a prior
	// successful Activate existed. Since the only successful Activate
	// in this test set v1 from the default newest (v2), history has 1
	// entry (v2). Assert that explicitly.
	prev, err := m.Rollback()
	if err != nil {
		t.Fatalf("Rollback after failure: %v", err)
	}
	if prev != "v2" {
		t.Fatalf("history corrupted by failed Activate: rollback returned %q want v2", prev)
	}
}

// ---------------------------------------------------------------------
// Failure: OPA rejects the rollback PUT. The history entry must be
// restored so the caller can retry.
// ---------------------------------------------------------------------
func TestRollback_PreservesHistoryOnOPAFailure(t *testing.T) {
	root := t.TempDir()
	writeVersionsWithContent(t, root, map[string]string{
		"v1": "package authz\n# v1 bundle\n",
		"v2": "package authz\n# v2 bundle\n",
	})

	srv, state := newMockOPAServer()
	defer srv.Close()

	admin := policy.NewOPAAdmin(srv.URL, zap.NewNop())
	m, _ := New(root)
	m.SetOPAAdmin(admin)

	if err := m.Activate("v1"); err != nil {
		t.Fatalf("Activate v1: %v", err)
	}

	state.mu.Lock()
	state.failNextPut = true
	state.mu.Unlock()

	if _, err := m.Rollback(); err == nil {
		t.Fatalf("expected rollback error on OPA failure")
	}
	if m.Active() != "v1" {
		t.Fatalf("Active() after failed rollback: got %q want v1", m.Active())
	}

	// A retry — now with OPA recovered — must succeed and actually
	// restore v2 (the history entry from the Activate above).
	prev, err := m.Rollback()
	if err != nil {
		t.Fatalf("retry Rollback: %v", err)
	}
	if prev != "v2" {
		t.Fatalf("retry Rollback returned %q want v2 (history was dropped on first failure)", prev)
	}
}

// ---------------------------------------------------------------------
// Unknown version: never hits OPA and never mutates in-memory state.
// ---------------------------------------------------------------------
func TestActivate_UnknownVersionDoesNotTouchOPA(t *testing.T) {
	root := t.TempDir()
	writeVersionsWithContent(t, root, map[string]string{
		"v1": "package authz\n",
	})

	srv, state := newMockOPAServer()
	defer srv.Close()

	admin := policy.NewOPAAdmin(srv.URL, zap.NewNop())
	m, _ := New(root)
	m.SetOPAAdmin(admin)

	if err := m.Activate("v99"); err == nil {
		t.Fatalf("expected error for unknown version")
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.putCount != 0 {
		t.Fatalf("OPA received %d PUTs for unknown version; expected 0", state.putCount)
	}
}

// ---------------------------------------------------------------------
// Nil admin: Activate / Rollback are still expected to work for
// dry-run / test use, just without touching OPA.
// ---------------------------------------------------------------------
func TestActivate_NoAdmin_StillFlipsPointer(t *testing.T) {
	root := writeVersions(t, "v1", "v2")
	m, _ := New(root)
	// No SetOPAAdmin.
	if err := m.Activate("v1"); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if m.Active() != "v1" {
		t.Fatalf("Active: got %q want v1", m.Active())
	}
}

// ---------------------------------------------------------------------
// Direct OPAAdmin coverage — the admin client exposes the exact REST
// surface the manager relies on, so a focused test pins its behaviour.
// ---------------------------------------------------------------------

func TestOPAAdmin_PutAndGet(t *testing.T) {
	srv, state := newMockOPAServer()
	defer srv.Close()

	admin := policy.NewOPAAdmin(srv.URL, zap.NewNop())
	ctx := context.Background()

	body := []byte("package authz\nallow := true\n")
	if err := admin.PutPolicy(ctx, "authz", body); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}

	state.mu.Lock()
	got := state.policies["authz"]
	state.mu.Unlock()
	if string(got) != string(body) {
		t.Fatalf("server stored %q, want %q", got, body)
	}

	round, err := admin.GetPolicy(ctx, "authz")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if string(round) != string(body) {
		t.Fatalf("GetPolicy returned %q, want %q", round, body)
	}
}

func TestOPAAdmin_DeleteIdempotent(t *testing.T) {
	srv, _ := newMockOPAServer()
	defer srv.Close()

	admin := policy.NewOPAAdmin(srv.URL, zap.NewNop())
	ctx := context.Background()

	// Delete before any PUT: mock returns 404, admin should treat as OK.
	if err := admin.DeletePolicy(ctx, "authz"); err != nil {
		t.Fatalf("DeletePolicy on empty store: %v", err)
	}

	if err := admin.PutPolicy(ctx, "authz", []byte("package authz\n")); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	if err := admin.DeletePolicy(ctx, "authz"); err != nil {
		t.Fatalf("DeletePolicy after PUT: %v", err)
	}
	// Second delete is again a 404 → OK.
	if err := admin.DeletePolicy(ctx, "authz"); err != nil {
		t.Fatalf("DeletePolicy idempotent call: %v", err)
	}
}

func TestOPAAdmin_PutPropagatesHTTPError(t *testing.T) {
	srv, state := newMockOPAServer()
	defer srv.Close()

	state.mu.Lock()
	state.failNextPut = true
	state.mu.Unlock()

	admin := policy.NewOPAAdmin(srv.URL, zap.NewNop())
	err := admin.PutPolicy(context.Background(), "authz", []byte("package authz\n"))
	if err == nil {
		t.Fatalf("expected error on simulated 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error should mention status code: %v", err)
	}
}

func TestOPAAdmin_PutRejectsEmpty(t *testing.T) {
	admin := policy.NewOPAAdmin("http://127.0.0.1:1", zap.NewNop())
	if err := admin.PutPolicy(context.Background(), "", []byte("x")); err == nil {
		t.Fatalf("expected error for empty id")
	}
	if err := admin.PutPolicy(context.Background(), "authz", nil); err == nil {
		t.Fatalf("expected error for empty body")
	}
}

// Small sanity check that the mock server is correctly wired — guards
// against false positives if the tests above silently skipped the OPA
// call path.
func TestMockOPAServer_Wired(t *testing.T) {
	srv, _ := newMockOPAServer()
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/policies/authz",
		strings.NewReader("package authz\n"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("mock OPA request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mock OPA status: %d", resp.StatusCode)
	}
}

// Compile-time assertion: *policy.OPAAdmin satisfies the narrow
// interface the manager depends on.
var _ OPAAdmin = (*policy.OPAAdmin)(nil)
