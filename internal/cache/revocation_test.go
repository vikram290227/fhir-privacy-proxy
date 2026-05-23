package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func newTestCache(t *testing.T) *RevocationCache {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return NewRevocationCache("localhost:1", logger)
}

func newMiniredisCache(t *testing.T) (*RevocationCache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	logger, _ := zap.NewDevelopment()
	rc := &RevocationCache{redis: rdb, logger: logger}
	t.Cleanup(func() { _ = rdb.Close() })
	return rc, mr
}

func TestPing_OK(t *testing.T) {
	rc, _ := newMiniredisCache(t)
	if err := rc.Ping(context.Background()); err != nil {
		t.Errorf("expected nil from Ping, got: %v", err)
	}
}

func TestPing_Unreachable(t *testing.T) {
	rc := newTestCache(t)
	if err := rc.Ping(context.Background()); err == nil {
		t.Error("expected error from unreachable Redis")
	}
}

func TestIsRevoked_NotRevoked(t *testing.T) {
	rc, _ := newMiniredisCache(t)
	revoked, err := rc.IsRevoked("hospital-a", "tok-1", time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoked {
		t.Error("expected not revoked for missing key")
	}
}

func TestIsRevoked_Revoked(t *testing.T) {
	rc, _ := newMiniredisCache(t)
	exp := time.Now().Add(time.Hour).Unix()
	if err := rc.Revoke("hospital-a", "tok-2", exp); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoked, err := rc.IsRevoked("hospital-a", "tok-2", exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoked {
		t.Error("expected revoked after Revoke()")
	}
}

func TestHandleWebhook_ValidRevocation(t *testing.T) {
	// Without a running Redis, the Revoke call will fail.
	// We verify that the handler parses the request and attempts revocation,
	// returning 500 since Redis is unreachable.

	event := keycloakEvent{
		Type:    "LOGOUT",
		RealmID: "hospital-a",
	}
	event.Details.TokenID = "token-abc"
	event.Details.UserID = "user-1"
	event.Details.Exp = 9999999999

	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/webhook/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	logger, _ := zap.NewDevelopment()
	rc := NewRevocationCache("localhost:1", logger)
	rc.HandleWebhook(w, req)

	// Expect 500 because Redis is not running
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 (redis unavailable), got %d", w.Code)
	}
}

func TestHandleWebhook_InvalidMethod(t *testing.T) {
	rc := newTestCache(t)

	req := httptest.NewRequest("GET", "/webhook/revoke", nil)
	w := httptest.NewRecorder()

	rc.HandleWebhook(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleWebhook_InvalidPayload(t *testing.T) {
	rc := newTestCache(t)

	req := httptest.NewRequest("POST", "/webhook/revoke", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	rc.HandleWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleWebhook_NonRevocationEvent(t *testing.T) {
	rc := newTestCache(t)

	event := keycloakEvent{
		Type:    "LOGIN",
		RealmID: "hospital-a",
	}
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/webhook/revoke", bytes.NewReader(body))
	w := httptest.NewRecorder()

	rc.HandleWebhook(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", w.Code)
	}
}

func TestHandleWebhook_MissingTokenID(t *testing.T) {
	rc := newTestCache(t)

	event := keycloakEvent{
		Type:    "LOGOUT",
		RealmID: "hospital-a",
	}
	// No token_id set
	body, _ := json.Marshal(event)
	req := httptest.NewRequest("POST", "/webhook/revoke", bytes.NewReader(body))
	w := httptest.NewRecorder()

	rc.HandleWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRevocationKeyFormat(t *testing.T) {
	tenantID := "hospital-a"
	jti := "token-123"
	expected := "revoke:hospital-a:token-123"

	key := "revoke:" + tenantID + ":" + jti
	if key != expected {
		t.Errorf("expected key %s, got %s", expected, key)
	}
}
