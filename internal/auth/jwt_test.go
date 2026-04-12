package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
)

// testJWTHelper spins up a local JWKS server and returns everything
// needed to mint test tokens signed with a key the proxy will trust.
type testJWTHelper struct {
	key       *rsa.PrivateKey
	issuer    string
	audience  string
	jwksURL   string
	keyID     string
	server    *httptest.Server
}

func newJWTHelper(t *testing.T) *testJWTHelper {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	h := &testJWTHelper{
		key:      k,
		keyID:    "test-key",
		audience: "fhir-privacy-proxy",
	}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{
					"kty": "RSA",
					"use": "sig",
					"alg": "RS256",
					"kid": h.keyID,
					"n":   base64URLEncode(k.PublicKey.N.Bytes()),
					"e":   base64URLEncode(big.NewInt(int64(k.PublicKey.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	h.issuer = h.server.URL
	h.jwksURL = h.server.URL + "/jwks"
	return h
}

func (h *testJWTHelper) close() { h.server.Close() }

func (h *testJWTHelper) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = h.keyID
	signed, err := token.SignedString(h.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func base64URLEncode(b []byte) string {
	// inline base64 URL encoder (no padding) to avoid extra imports
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 0, (len(b)+2)/3*4)
	var val uint32
	var bits int
	for _, c := range b {
		val = (val << 8) | uint32(c)
		bits += 8
		for bits >= 6 {
			bits -= 6
			out = append(out, alphabet[(val>>bits)&0x3F])
		}
	}
	if bits > 0 {
		out = append(out, alphabet[(val<<(6-bits))&0x3F])
	}
	return string(out)
}

// buildRegistry wires the test tenant config into a Registry the
// middleware can resolve by issuer URL.
func buildRegistry(t *testing.T, h *testJWTHelper) *tenant.Registry {
	t.Helper()
	yaml := fmt.Sprintf(`tenants:
  - issuer_url: "%s"
    tenant_id: "test-tenant"
    jwks_endpoint: "%s"
    audience: "%s"
    policy_bundle: "test"
    allowed_scopes:
      - "patient/Patient.read"
`, h.issuer, h.server.URL, h.audience)
	dir := t.TempDir()
	path := fmt.Sprintf("%s/tenants.yaml", dir)
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	reg, err := tenant.LoadRegistry(path)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return reg
}

// TestJWTValidation_MissingIssuer verifies the middleware rejects
// tokens that omit the iss claim entirely.
func TestJWTValidation_MissingIssuer(t *testing.T) {
	h := newJWTHelper(t)
	defer h.close()

	reg := buildRegistry(t, h)
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(reg, logger)

	token := h.sign(t, jwt.MapClaims{
		"sub": "nurse1",
		"aud": h.audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	_, _, err := m.validateJWT(token)
	if err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

// TestJWTValidation_UntrustedIssuer verifies tokens signed for an
// unknown issuer are rejected before reaching JWKS validation.
func TestJWTValidation_UntrustedIssuer(t *testing.T) {
	h := newJWTHelper(t)
	defer h.close()

	reg := buildRegistry(t, h)
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(reg, logger)

	token := h.sign(t, jwt.MapClaims{
		"iss": "http://evil-issuer.example.com",
		"sub": "nurse1",
		"aud": h.audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	_, _, err := m.validateJWT(token)
	if err == nil {
		t.Fatal("expected error for untrusted issuer")
	}
}

// TestJWTValidation_Expired verifies expired tokens are rejected.
func TestJWTValidation_Expired(t *testing.T) {
	h := newJWTHelper(t)
	defer h.close()

	reg := buildRegistry(t, h)
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(reg, logger)

	token := h.sign(t, jwt.MapClaims{
		"iss": h.issuer,
		"sub": "nurse1",
		"aud": h.audience,
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	_, _, err := m.validateJWT(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

// TestJWTValidation_InvalidSignature verifies tokens signed with a
// different key are rejected.
func TestJWTValidation_InvalidSignature(t *testing.T) {
	h := newJWTHelper(t)
	defer h.close()

	// Mint a token with a completely different key that the JWKS
	// server does NOT advertise.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := jwt.MapClaims{
		"iss": h.issuer,
		"sub": "nurse1",
		"aud": h.audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = h.keyID // advertise our kid but sign with a different key
	signed, _ := tok.SignedString(otherKey)

	reg := buildRegistry(t, h)
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(reg, logger)

	_, _, err := m.validateJWT(signed)
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

// TestJWTValidation_Valid verifies a well-formed token signed with
// the trusted key is accepted and the claims are returned.
func TestJWTValidation_Valid(t *testing.T) {
	h := newJWTHelper(t)
	defer h.close()

	reg := buildRegistry(t, h)
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(reg, logger)

	token := h.sign(t, jwt.MapClaims{
		"iss": h.issuer,
		"sub": "nurse1",
		"aud": h.audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"jti": "abc",
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"nurse"},
		},
		"fhirContext": map[string]interface{}{
			"department": "cardiology",
			"role":       "nurse",
			"facility":   "main",
		},
		"scope": "patient/Patient.read",
	})

	claims, cfg, err := m.validateJWT(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TenantID != "test-tenant" {
		t.Errorf("expected tenant_id test-tenant, got %s", cfg.TenantID)
	}
	if claims["sub"] != "nurse1" {
		t.Errorf("expected sub nurse1, got %v", claims["sub"])
	}
}
