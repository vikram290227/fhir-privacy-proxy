package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestOPAAdmin_PutPolicy_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "text/plain" {
			t.Errorf("expected text/plain, got %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin(server.URL, logger)

	err := admin.PutPolicy(context.Background(), "authz", []byte("package authz\nallow := true\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOPAAdmin_PutPolicy_EmptyID(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin("http://localhost:1", logger)

	err := admin.PutPolicy(context.Background(), "", []byte("package authz\n"))
	if err == nil {
		t.Error("expected error for empty policy id")
	}
}

func TestOPAAdmin_PutPolicy_EmptyBody(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin("http://localhost:1", logger)

	err := admin.PutPolicy(context.Background(), "authz", nil)
	if err == nil {
		t.Error("expected error for empty rego body")
	}
}

func TestOPAAdmin_PutPolicy_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin(server.URL, logger)

	err := admin.PutPolicy(context.Background(), "authz", []byte("package authz\n"))
	if err == nil {
		t.Error("expected error for server error response")
	}
}

func TestOPAAdmin_PutPolicy_Unreachable(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin("http://localhost:1", logger)

	err := admin.PutPolicy(context.Background(), "authz", []byte("package authz\n"))
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestOPAAdmin_DeletePolicy_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin(server.URL, logger)

	err := admin.DeletePolicy(context.Background(), "authz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOPAAdmin_DeletePolicy_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin(server.URL, logger)

	// 404 treated as success
	err := admin.DeletePolicy(context.Background(), "authz")
	if err != nil {
		t.Fatalf("unexpected error for 404: %v", err)
	}
}

func TestOPAAdmin_DeletePolicy_EmptyID(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin("http://localhost:1", logger)

	err := admin.DeletePolicy(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty policy id")
	}
}

func TestOPAAdmin_DeletePolicy_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("oops"))
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin(server.URL, logger)

	err := admin.DeletePolicy(context.Background(), "authz")
	if err == nil {
		t.Error("expected error for server error")
	}
}

func TestOPAAdmin_GetPolicy_Success(t *testing.T) {
	expected := []byte("package authz\nallow := true\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(expected)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin(server.URL, logger)

	body, err := admin.GetPolicy(context.Background(), "authz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != string(expected) {
		t.Errorf("expected %q, got %q", expected, body)
	}
}

func TestOPAAdmin_GetPolicy_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin(server.URL, logger)

	_, err := admin.GetPolicy(context.Background(), "authz")
	if err == nil {
		t.Error("expected error for 404")
	}
}

func TestOPAAdmin_GetPolicy_Unreachable(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin("http://localhost:1", logger)

	_, err := admin.GetPolicy(context.Background(), "authz")
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestNewOPAAdmin(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	admin := NewOPAAdmin("http://opa:8181", logger)
	if admin == nil {
		t.Error("expected non-nil admin")
	}
	if admin.baseURL != "http://opa:8181" {
		t.Errorf("unexpected baseURL: %s", admin.baseURL)
	}
}
