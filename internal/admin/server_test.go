package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/metrics"
	"github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
)

// ---------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------

type fakePolicyManager struct {
	bundles      []Bundle
	active       string
	activateErr  error
	rollbackErr  error
	rollbackPrev string
	activateCall string
	rollbackHit  int
}

func (f *fakePolicyManager) List() []Bundle    { return f.bundles }
func (f *fakePolicyManager) Active() string    { return f.active }
func (f *fakePolicyManager) Activate(v string) error {
	f.activateCall = v
	if f.activateErr != nil {
		return f.activateErr
	}
	f.active = v
	return nil
}
func (f *fakePolicyManager) Rollback() (string, error) {
	f.rollbackHit++
	if f.rollbackErr != nil {
		return "", f.rollbackErr
	}
	f.active = f.rollbackPrev
	return f.rollbackPrev, nil
}

type fakeAuditTailer struct{ path string }

func (f *fakeAuditTailer) Path() string { return f.path }

type fakeRevoker struct {
	gotTenant string
	gotJTI    string
	gotExp    int64
	err       error
}

func (f *fakeRevoker) Revoke(tenantID, jti string, exp int64) error {
	f.gotTenant = tenantID
	f.gotJTI = jti
	f.gotExp = exp
	return f.err
}

type fakeHealth struct {
	err   error
	calls int32
	mu    sync.Mutex
}

func (f *fakeHealth) HealthCheck(ctx context.Context) error {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.err
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

const testAPIKey = "test-admin-key"

func newServerForTest(t *testing.T, deps Deps) *Server {
	t.Helper()
	return New(testAPIKey, deps, zap.NewNop())
}

func adminRequest(t *testing.T, srv *Server, method, target string, body any, withKey bool) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = strings.NewReader(string(buf))
	}
	req := httptest.NewRequest(method, target, reader)
	if withKey {
		req.Header.Set("X-Admin-Key", testAPIKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response: %v\nbody=%s", err, rec.Body.String())
	}
}

// ---------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------

func TestRequireAPIKey_RejectsMissingHeader(t *testing.T) {
	srv := newServerForTest(t, Deps{})
	rec := adminRequest(t, srv, http.MethodGet, "/policy/versions", nil, false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
	}
}

func TestRequireAPIKey_RejectsWrongKey(t *testing.T) {
	srv := newServerForTest(t, Deps{})
	req := httptest.NewRequest(http.MethodGet, "/policy/versions", nil)
	req.Header.Set("X-Admin-Key", "wrong")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
	}
}

func TestRequireAPIKey_RejectsEmptyConfiguredKey(t *testing.T) {
	// Server with no key configured must reject every request even
	// when the client doesn't supply a header — defense in depth
	// against a wiring mistake in main.go.
	srv := New("", Deps{}, zap.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/policy/versions", nil)
	req.Header.Set("X-Admin-Key", "anything")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rec.Code)
	}
}

// ---------------------------------------------------------------------
// /policy/versions
// ---------------------------------------------------------------------

func TestListVersions(t *testing.T) {
	pm := &fakePolicyManager{
		active: "v2",
		bundles: []Bundle{
			{Version: "v1", Path: "/policies/versions/v1"},
			{Version: "v2", Path: "/policies/versions/v2"},
		},
	}
	srv := newServerForTest(t, Deps{Policy: pm})
	rec := adminRequest(t, srv, http.MethodGet, "/policy/versions", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp listVersionsResponse
	decodeJSON(t, rec, &resp)
	if resp.Active != "v2" {
		t.Fatalf("active: got %q want v2", resp.Active)
	}
	if len(resp.Bundles) != 2 {
		t.Fatalf("bundles: got %d want 2", len(resp.Bundles))
	}
}

func TestListVersions_FeatureDisabledWhenNoPolicyManager(t *testing.T) {
	srv := newServerForTest(t, Deps{})
	rec := adminRequest(t, srv, http.MethodGet, "/policy/versions", nil, true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503", rec.Code)
	}
}

// ---------------------------------------------------------------------
// /policy/activate
// ---------------------------------------------------------------------

func TestActivate_Success(t *testing.T) {
	pm := &fakePolicyManager{}
	srv := newServerForTest(t, Deps{Policy: pm})
	rec := adminRequest(t, srv, http.MethodPost, "/policy/activate",
		map[string]string{"version": "v3"}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
	}
	if pm.activateCall != "v3" {
		t.Fatalf("Activate called with %q want v3", pm.activateCall)
	}
	var resp activateResponse
	decodeJSON(t, rec, &resp)
	if resp.Active != "v3" {
		t.Fatalf("response active: got %q want v3", resp.Active)
	}
}

func TestActivate_BadRequestOnMissingVersion(t *testing.T) {
	pm := &fakePolicyManager{}
	srv := newServerForTest(t, Deps{Policy: pm})
	rec := adminRequest(t, srv, http.MethodPost, "/policy/activate",
		map[string]string{}, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
	if pm.activateCall != "" {
		t.Fatalf("Activate should not be called; got %q", pm.activateCall)
	}
}

func TestActivate_PropagatesError(t *testing.T) {
	pm := &fakePolicyManager{activateErr: errors.New("opa down")}
	srv := newServerForTest(t, Deps{Policy: pm})
	rec := adminRequest(t, srv, http.MethodPost, "/policy/activate",
		map[string]string{"version": "v3"}, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "opa down") {
		t.Fatalf("error not surfaced: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------
// /policy/rollback
// ---------------------------------------------------------------------

func TestRollback_Success(t *testing.T) {
	pm := &fakePolicyManager{rollbackPrev: "v1"}
	srv := newServerForTest(t, Deps{Policy: pm})
	rec := adminRequest(t, srv, http.MethodPost, "/policy/rollback", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp rollbackResponse
	decodeJSON(t, rec, &resp)
	if resp.Previous != "v1" {
		t.Fatalf("previous: got %q want v1", resp.Previous)
	}
	if pm.rollbackHit != 1 {
		t.Fatalf("Rollback should be called once; got %d", pm.rollbackHit)
	}
}

func TestRollback_ConflictWhenNoHistory(t *testing.T) {
	pm := &fakePolicyManager{rollbackErr: errors.New("no previous version")}
	srv := newServerForTest(t, Deps{Policy: pm})
	rec := adminRequest(t, srv, http.MethodPost, "/policy/rollback", nil, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409", rec.Code)
	}
}

// ---------------------------------------------------------------------
// /tenants
// ---------------------------------------------------------------------

func TestListTenants_RedactsSecrets(t *testing.T) {
	tmp := t.TempDir()
	yamlPath := filepath.Join(tmp, "tenants.yaml")
	yaml := `tenants:
  - tenant_id: hospital-a
    issuer_url: https://idp/realms/a
    jwks_endpoint: https://idp/realms/a/keys
    audience: fhir-a
    allowed_scopes: ["patient/*.read"]
    requests_per_minute: 30
    requests_per_hour: 600
    sensitive_patients: ["111","222","333"]
  - tenant_id: hospital-b
    issuer_url: https://idp/realms/b
    audience: fhir-b
    sensitive_patients: ["999"]
`
	if err := os.WriteFile(yamlPath, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := tenant.LoadRegistry(yamlPath)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}

	srv := newServerForTest(t, Deps{Tenants: reg})
	rec := adminRequest(t, srv, http.MethodGet, "/tenants", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp listTenantsResponse
	decodeJSON(t, rec, &resp)
	if len(resp.Tenants) != 2 {
		t.Fatalf("tenants: got %d want 2", len(resp.Tenants))
	}
	// Stable order from sort.
	if resp.Tenants[0].TenantID != "hospital-a" || resp.Tenants[1].TenantID != "hospital-b" {
		t.Fatalf("order broken: %+v", resp.Tenants)
	}
	// The actual sensitive list MUST NOT appear in the wire response;
	// only the count.
	body := rec.Body.String()
	for _, leaked := range []string{"111", "222", "333", "999"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("sensitive id %q leaked in /tenants response: %s", leaked, body)
		}
	}
	if resp.Tenants[0].SensitivePatientsCount != 3 {
		t.Fatalf("sensitive count for a: got %d want 3", resp.Tenants[0].SensitivePatientsCount)
	}
	if resp.Tenants[1].SensitivePatientsCount != 1 {
		t.Fatalf("sensitive count for b: got %d want 1", resp.Tenants[1].SensitivePatientsCount)
	}
}

// ---------------------------------------------------------------------
// /audit/tail
// ---------------------------------------------------------------------

func TestAuditTail_ReturnsLastNLines(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "audit.log")
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, fmt.Sprintf(`{"event":%d}`, i))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := newServerForTest(t, Deps{Audit: &fakeAuditTailer{path: path}})
	rec := adminRequest(t, srv, http.MethodGet, "/audit/tail?n=5", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp auditTailResponse
	decodeJSON(t, rec, &resp)
	if len(resp.Lines) != 5 {
		t.Fatalf("lines: got %d want 5", len(resp.Lines))
	}
	if resp.Lines[0] != `{"event":195}` {
		t.Fatalf("first line should be event 195, got %q", resp.Lines[0])
	}
	if resp.Lines[4] != `{"event":199}` {
		t.Fatalf("last line should be event 199, got %q", resp.Lines[4])
	}
}

func TestAuditTail_DefaultsTo50(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "audit.log")
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, fmt.Sprintf(`{"event":%d}`, i))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := newServerForTest(t, Deps{Audit: &fakeAuditTailer{path: path}})
	rec := adminRequest(t, srv, http.MethodGet, "/audit/tail", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	var resp auditTailResponse
	decodeJSON(t, rec, &resp)
	if len(resp.Lines) != 50 {
		t.Fatalf("default n should be 50; got %d", len(resp.Lines))
	}
}

func TestAuditTail_RejectsInvalidN(t *testing.T) {
	srv := newServerForTest(t, Deps{Audit: &fakeAuditTailer{path: "/dev/null"}})
	rec := adminRequest(t, srv, http.MethodGet, "/audit/tail?n=notanumber", nil, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
}

func TestAuditTail_FeatureDisabledWhenNoSink(t *testing.T) {
	srv := newServerForTest(t, Deps{})
	rec := adminRequest(t, srv, http.MethodGet, "/audit/tail", nil, true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503", rec.Code)
	}
}

// ---------------------------------------------------------------------
// /tokens/revoke
// ---------------------------------------------------------------------

func TestRevokeToken_Success(t *testing.T) {
	rev := &fakeRevoker{}
	srv := newServerForTest(t, Deps{Revoker: rev})
	body := map[string]any{
		"tenant": "hospital-a",
		"jti":    "abc-123",
		"exp":    int64(9999999999),
	}
	rec := adminRequest(t, srv, http.MethodPost, "/tokens/revoke", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rec.Code, rec.Body.String())
	}
	if rev.gotTenant != "hospital-a" || rev.gotJTI != "abc-123" || rev.gotExp != 9999999999 {
		t.Fatalf("revoker received wrong args: %+v", rev)
	}
}

func TestRevokeToken_RejectsMissingFields(t *testing.T) {
	rev := &fakeRevoker{}
	srv := newServerForTest(t, Deps{Revoker: rev})
	rec := adminRequest(t, srv, http.MethodPost, "/tokens/revoke",
		map[string]any{"tenant": "hospital-a"}, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
}

func TestRevokeToken_RejectsZeroExp(t *testing.T) {
	rev := &fakeRevoker{}
	srv := newServerForTest(t, Deps{Revoker: rev})
	rec := adminRequest(t, srv, http.MethodPost, "/tokens/revoke",
		map[string]any{"tenant": "hospital-a", "jti": "x", "exp": 0}, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
}

func TestRevokeToken_FeatureDisabledWhenNoRevoker(t *testing.T) {
	srv := newServerForTest(t, Deps{})
	rec := adminRequest(t, srv, http.MethodPost, "/tokens/revoke",
		map[string]any{"tenant": "a", "jti": "j", "exp": 1}, true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503", rec.Code)
	}
}

// ---------------------------------------------------------------------
// /health/deps
// ---------------------------------------------------------------------

func TestHealthDeps_AllOK(t *testing.T) {
	deps := Deps{
		OPA:      &fakeHealth{},
		Redis:    &fakeHealth{},
		Upstream: &fakeHealth{},
		Risk:     &fakeHealth{},
	}
	srv := newServerForTest(t, deps)
	rec := adminRequest(t, srv, http.MethodGet, "/health/deps", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 body=%s", rec.Code, rec.Body.String())
	}
	var resp healthDepsResponse
	decodeJSON(t, rec, &resp)
	if !resp.OK {
		t.Fatalf("ok flag should be true")
	}
	for _, name := range []string{"opa", "redis", "upstream", "risk"} {
		if resp.Deps[name].Status != "ok" {
			t.Fatalf("%s: got status %q want ok", name, resp.Deps[name].Status)
		}
	}
}

func TestHealthDeps_OneFailingDepFails503(t *testing.T) {
	deps := Deps{
		OPA:   &fakeHealth{},
		Redis: &fakeHealth{err: errors.New("connection refused")},
	}
	srv := newServerForTest(t, deps)
	rec := adminRequest(t, srv, http.MethodGet, "/health/deps", nil, true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503", rec.Code)
	}
	var resp healthDepsResponse
	decodeJSON(t, rec, &resp)
	if resp.OK {
		t.Fatalf("ok flag should be false")
	}
	if resp.Deps["redis"].Status != "error" {
		t.Fatalf("redis status: got %q want error", resp.Deps["redis"].Status)
	}
	if !strings.Contains(resp.Deps["redis"].Error, "connection refused") {
		t.Fatalf("redis error not propagated: %q", resp.Deps["redis"].Error)
	}
	if resp.Deps["upstream"].Status != "disabled" {
		t.Fatalf("upstream status: got %q want disabled", resp.Deps["upstream"].Status)
	}
}

func TestHealthDeps_AllDisabledStill200(t *testing.T) {
	srv := newServerForTest(t, Deps{})
	rec := adminRequest(t, srv, http.MethodGet, "/health/deps", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", rec.Code)
	}
	var resp healthDepsResponse
	decodeJSON(t, rec, &resp)
	if !resp.OK {
		t.Fatalf("all-disabled should still report ok=true")
	}
}

// ---------------------------------------------------------------------
// HTTP-based HealthCheck adapter
// ---------------------------------------------------------------------

func TestHTTPHealthCheck_OKOnNon5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	hc := NewHTTPHealthCheck(ts.URL + "/health")
	if err := hc.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestHTTPHealthCheck_ErrorOn5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	hc := NewHTTPHealthCheck(ts.URL)
	err := hc.HealthCheck(context.Background())
	if err == nil {
		t.Fatalf("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error should mention 500: %v", err)
	}
}

func TestHTTPHealthCheck_NilForEmptyURL(t *testing.T) {
	if hc := NewHTTPHealthCheck(""); hc != nil {
		t.Fatalf("empty url should produce nil")
	}
}

// ---------------------------------------------------------------------
// Metrics — confirm the counter is incremented with the route pattern,
// not the raw path (so /audit/tail?n=5 doesn't explode label cardinality).
// ---------------------------------------------------------------------

func TestInstrumentMiddleware_UsesRoutePattern(t *testing.T) {
	pm := &fakePolicyManager{
		active: "v1",
		bundles: []Bundle{{Version: "v1", Path: "/x"}},
	}
	srv := newServerForTest(t, Deps{
		Policy: pm,
		Audit:  &fakeAuditTailer{path: writeTinyAudit(t)},
	})

	// Hit the same route pattern twice with different query strings.
	for _, n := range []int{1, 2} {
		rec := adminRequest(t, srv, http.MethodGet, "/audit/tail?n="+strconv.Itoa(n), nil, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("n=%d status: %d body=%s", n, rec.Code, rec.Body.String())
		}
	}

	// Give Prometheus a microsecond to settle (counter writes are
	// sync but the test guards against any future buffering).
	time.Sleep(time.Millisecond)

	// Use the metric registry directly to assert the label is the
	// chi route pattern, not the raw path.
	got := readCounter(t, "/audit/tail", "200")
	if got < 2 {
		t.Fatalf("counter for endpoint=/audit/tail status=200: got %v want >= 2", got)
	}
}

func writeTinyAudit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "a.log")
	if err := os.WriteFile(p, []byte("{\"event\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// readCounter returns the current value of the AdminRequests counter
// for the given (endpoint, status) labels.
func readCounter(t *testing.T, endpoint, status string) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.AdminRequests.WithLabelValues(endpoint, status))
}
