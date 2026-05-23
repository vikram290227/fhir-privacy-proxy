# FHIR Privacy Proxy — Claude Code Task List
## Complete Build Instructions for a Fully Working Application

**Repository**: https://github.com/vikram290227/fhir-privacy-proxy
**Language**: Go 1.22 (proxy), Python 3.11 (ML service), Rego (OPA policies)
**Start every session by running**: `make up` then `curl http://localhost:8080/health`

---

## HOW TO USE THIS LIST

Give Claude Code this file at the start of every session. Each task has:
- **CONTEXT**: What already exists so Claude Code doesn't re-build it
- **TASK**: Exactly what to build
- **ACCEPTANCE**: How to verify it works before moving on
- **FILES**: Which files to create or modify

Work through tasks in order. Do not skip tasks. Each task builds on the previous one.

---

## PHASE 1 — STABILITY AND CORRECTNESS (Do First)
*The proxy runs but has gaps that will cause failures in a demo or production setting.*

---

### TASK 1.1 — Fix go.mod module path and verify the project compiles clean

**CONTEXT**:
The module is declared as `github.com/YOUR_USERNAME/fhir-privacy-proxy` in go.mod but the actual GitHub username is `vikram290227`. All internal imports reference the wrong path.

**TASK**:
1. Open `go.mod`. Change the module line from `github.com/YOUR_USERNAME/fhir-privacy-proxy` to `github.com/vikram290227/fhir-privacy-proxy`
2. Run `grep -r "YOUR_USERNAME" --include="*.go" .` to find all Go files with the wrong import path
3. Replace every occurrence of `YOUR_USERNAME` with `vikram290227` across all `.go` files
4. Run `go build ./...` — it must produce zero errors
5. Run `go vet ./...` — it must produce zero warnings

**ACCEPTANCE**:
```bash
go build ./...   # exits 0, no output
go vet ./...     # exits 0, no output
```

**FILES**: `go.mod`, every `.go` file found by grep

---

### TASK 1.2 — Implement `internal/auth/jwt_validator.go` (currently stubbed)

**CONTEXT**:
`internal/auth/middleware.go` calls `m.validateJWT(tokenString)` which is declared in the file but returns `fmt.Errorf("not implemented")`. This means every request currently fails with a 401. The dependency `github.com/MicahParks/keyfunc/v2` is in go.mod.

**TASK**:
Create `internal/auth/jwt_validator.go` with a complete implementation:

```go
package auth

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/MicahParks/keyfunc/v2"
    "github.com/golang-jwt/jwt/v5"
    "go.uber.org/zap"

    "github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
)

type JWTValidator struct {
    mu        sync.RWMutex
    jwksCache map[string]*keyfunc.JWKS // keyed by tenant_id
    logger    *zap.Logger
}

func NewJWTValidator(logger *zap.Logger) *JWTValidator {
    return &JWTValidator{
        jwksCache: make(map[string]*keyfunc.JWKS),
        logger:    logger,
    }
}

// ValidateToken decodes the raw JWT string, looks up the tenant by issuer,
// fetches (and caches) JWKS, verifies the RS256 signature, validates
// standard claims (exp, nbf, aud, iss), and returns the verified claims
// plus the matching tenant config.
func (v *JWTValidator) ValidateToken(
    ctx context.Context,
    tokenString string,
    registry *tenant.Registry,
) (jwt.MapClaims, *tenant.Config, error) {

    // Step 1: decode header only (no sig check) to get issuer
    unverified, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
    if err != nil {
        return nil, nil, fmt.Errorf("malformed token: %w", err)
    }
    rawClaims, ok := unverified.Claims.(jwt.MapClaims)
    if !ok {
        return nil, nil, fmt.Errorf("invalid claims type")
    }
    issuer, _ := rawClaims["iss"].(string)
    if issuer == "" {
        return nil, nil, fmt.Errorf("missing iss claim")
    }

    // Step 2: resolve tenant
    tenantCfg, err := registry.GetByIssuer(issuer)
    if err != nil {
        return nil, nil, fmt.Errorf("untrusted issuer %q: %w", issuer, err)
    }

    // Step 3: get or create JWKS keyfunc
    jwks, err := v.getJWKS(tenantCfg)
    if err != nil {
        return nil, nil, fmt.Errorf("jwks fetch failed: %w", err)
    }

    // Step 4: verify signature and standard claims
    token, err := jwt.Parse(
        tokenString,
        jwks.Keyfunc,
        jwt.WithValidMethods([]string{"RS256"}),
        jwt.WithAudience(tenantCfg.Audience),
        jwt.WithIssuedAt(),
        jwt.WithExpirationRequired(),
    )
    if err != nil {
        return nil, nil, fmt.Errorf("token validation failed: %w", err)
    }
    if !token.Valid {
        return nil, nil, fmt.Errorf("token is not valid")
    }

    verified := token.Claims.(jwt.MapClaims)
    return verified, tenantCfg, nil
}

func (v *JWTValidator) getJWKS(cfg *tenant.Config) (*keyfunc.JWKS, error) {
    v.mu.RLock()
    if jwks, ok := v.jwksCache[cfg.TenantID]; ok {
        v.mu.RUnlock()
        return jwks, nil
    }
    v.mu.RUnlock()

    v.mu.Lock()
    defer v.mu.Unlock()

    // double-check after acquiring write lock
    if jwks, ok := v.jwksCache[cfg.TenantID]; ok {
        return jwks, nil
    }

    jwks, err := keyfunc.Get(cfg.JWKSEndpoint, keyfunc.Options{
        RefreshInterval:   15 * time.Minute,
        RefreshRateLimit:  time.Minute,
        RefreshUnknownKID: true,
    })
    if err != nil {
        return nil, fmt.Errorf("keyfunc.Get(%s): %w", cfg.JWKSEndpoint, err)
    }
    v.jwksCache[cfg.TenantID] = jwks
    v.logger.Info("jwks cached", zap.String("tenant", cfg.TenantID))
    return jwks, nil
}
```

Update `middleware.go` so it creates a `JWTValidator` and calls `ValidateToken` instead of returning "not implemented".

**ACCEPTANCE**:
```bash
# With docker-compose running:
./scripts/get_token.sh nurse1 password
# should return a JWT, not an error

TOKEN=$(./scripts/get_token.sh nurse1 password | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/fhir/r4/Patient/test
# should return 200 or a FHIR error, NOT 401 "not implemented"
```

**FILES**: `internal/auth/jwt_validator.go` (new), `internal/auth/middleware.go` (update validateJWT call)

---

### TASK 1.3 — Implement `internal/tenant/registry.go` YAML loading (currently hardcoded)

**CONTEXT**:
`tenant.LoadRegistry()` exists but either reads a hardcoded map or the YAML parsing is not complete. `configs/tenants.yaml` exists with real content.

**TASK**:
Ensure `LoadRegistry(path string)` does the following:
1. Reads the file at `path` using `os.ReadFile`
2. Unmarshals using `gopkg.in/yaml.v3`
3. Validates required fields: `issuer_url`, `tenant_id`, `jwks_endpoint`, `audience`
4. Returns an error (not panic) if any tenant is missing a required field
5. Logs the count of loaded tenants at INFO level
6. The `Registry` struct must expose `GetByIssuer(issuer string) (*Config, error)` using a `sync.RWMutex`-protected map

The `Config` struct must include all fields present in `configs/tenants.yaml`:
```go
type Config struct {
    IssuerURL          string   `yaml:"issuer_url"`
    TenantID           string   `yaml:"tenant_id"`
    JWKSEndpoint       string   `yaml:"jwks_endpoint"`
    Audience           string   `yaml:"audience"`
    PolicyBundle       string   `yaml:"policy_bundle"`
    AllowedScopes      []string `yaml:"allowed_scopes"`
    AllowedDepartments []string `yaml:"allowed_departments"`
    SensitivePatients  []string `yaml:"sensitive_patients"`
    RequestsPerMinute  int      `yaml:"requests_per_minute"`
    RequestsPerHour    int      `yaml:"requests_per_hour"`
}
```

**ACCEPTANCE**:
```bash
go test ./internal/tenant/... -v
# Must pass a test that loads configs/tenants.yaml and finds hospital-a
```

Write the test at `internal/tenant/registry_test.go`.

**FILES**: `internal/tenant/registry.go`, `internal/tenant/registry_test.go`

---

### TASK 1.4 — Implement `internal/auth/context_builder.go`

**CONTEXT**:
`buildSubjectContext()` in `middleware.go` returns "not implemented". This function must extract all claims from the verified JWT and build a `SubjectContext` struct.

**TASK**:
Create `internal/auth/context_builder.go`:

```go
package auth

import (
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
)

func buildSubjectContext(
    claims jwt.MapClaims,
    cfg *tenant.Config,
    r *http.Request,
) (*SubjectContext, error) {

    // 1. Required: subject
    sub, _ := claims["sub"].(string)
    if sub == "" {
        return nil, fmt.Errorf("missing sub claim")
    }

    // 2. Roles — try resource_access first, fall back to realm_access
    roles := extractRoles(claims, cfg.TenantID)

    // 3. fhirContext custom claim
    fhirCtx := extractFHIRContext(claims)
    if fhirCtx.Department == "" {
        return nil, fmt.Errorf("missing fhirContext.department claim")
    }

    // 4. Validate department against tenant whitelist (if configured)
    if len(cfg.AllowedDepartments) > 0 && !contains(cfg.AllowedDepartments, fhirCtx.Department) {
        return nil, fmt.Errorf("department %q not permitted for tenant %s", fhirCtx.Department, cfg.TenantID)
    }

    // 5. Scopes
    scopes := strings.Fields(stringClaim(claims, "scope"))

    // 6. Session metadata
    iat := int64Claim(claims, "iat")
    exp := int64Claim(claims, "exp")

    ctx := &SubjectContext{
        SubjectID:   sub,
        SubjectType: "practitioner",
        Roles:       roles,
        HasRoles:    len(roles) > 0,
        FHIRContext: fhirCtx,
        Client: ClientInfo{
            ID:   stringClaim(claims, "azp", "client_id"),
        },
        Scopes: scopes,
        Session: SessionInfo{
            TokenID:   stringClaim(claims, "jti"),
            IssuedAt:  time.Unix(iat, 0),
            ExpiresAt: time.Unix(exp, 0),
        },
        TenantID: cfg.TenantID,
    }

    // 7. Break-glass detection
    if r.Header.Get("X-Break-Glass") == "true" {
        if !contains(roles, "can_break_glass") {
            return nil, fmt.Errorf("break-glass attempted without can_break_glass role")
        }
        justification := r.Header.Get("X-Break-Glass-Justification")
        if len(justification) < 20 {
            return nil, fmt.Errorf("break-glass justification must be at least 20 characters")
        }
        if len(justification) > 500 {
            return nil, fmt.Errorf("break-glass justification must not exceed 500 characters")
        }
        ctx.BreakGlass = &BreakGlassContext{
            Enabled:       true,
            Justification: justification,
            RequestedBy:   sub,
        }
    }

    return ctx, nil
}

func extractRoles(claims jwt.MapClaims, clientID string) []string {
    // Try resource_access.<clientID>.roles first
    if ra, ok := claims["resource_access"].(map[string]interface{}); ok {
        if client, ok := ra[clientID].(map[string]interface{}); ok {
            if rolesList, ok := client["roles"].([]interface{}); ok {
                return toStringSlice(rolesList)
            }
        }
    }
    // Fallback: realm_access.roles
    if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
        if rolesList, ok := ra["roles"].([]interface{}); ok {
            return toStringSlice(rolesList)
        }
    }
    return nil
}

func extractFHIRContext(claims jwt.MapClaims) FHIRContext {
    fc := FHIRContext{
        Facility:    "main-hospital",
        SessionType: "clinical",
    }
    raw, ok := claims["fhirContext"].(map[string]interface{})
    if !ok {
        return fc
    }
    if v, ok := raw["department"].(string); ok {
        fc.Department = v
    }
    if v, ok := raw["role"].(string); ok {
        fc.Role = v
    }
    if v, ok := raw["facility"].(string); ok {
        fc.Facility = v
    }
    if v, ok := raw["sessionType"].(string); ok {
        fc.SessionType = v
    }
    return fc
}

// helpers
func stringClaim(claims jwt.MapClaims, keys ...string) string {
    for _, k := range keys {
        if v, ok := claims[k].(string); ok && v != "" {
            return v
        }
    }
    return ""
}

func int64Claim(claims jwt.MapClaims, key string) int64 {
    if v, ok := claims[key].(float64); ok {
        return int64(v)
    }
    return 0
}

func toStringSlice(in []interface{}) []string {
    out := make([]string, 0, len(in))
    for _, v := range in {
        if s, ok := v.(string); ok {
            out = append(out, s)
        }
    }
    return out
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}
```

**ACCEPTANCE**:
```bash
go test ./internal/auth/... -v -run TestBuildSubjectContext
```

Write tests covering: valid token, missing department, break-glass valid, break-glass no role, break-glass short justification.

**FILES**: `internal/auth/context_builder.go` (new), `internal/auth/context_builder_test.go` (new)

---

### TASK 1.5 — Implement `internal/policy/opa_client.go`

**CONTEXT**:
The middleware calls `opaClient.Evaluate(...)` but the OPA client either doesn't exist or isn't wired up. OPA runs as a separate container at `http://opa:8181`.

**TASK**:
Create `internal/policy/opa_client.go`:

```go
package policy

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "go.uber.org/zap"
)

type OPAClient struct {
    endpoint   string
    httpClient *http.Client
    logger     *zap.Logger
}

type Decision struct {
    Allow  bool     `json:"allow"`
    Remove []string `json:"remove"`
    Mask   []string `json:"mask"`
    Reason string   `json:"reason"`
}

func NewOPAClient(endpoint string, logger *zap.Logger) *OPAClient {
    return &OPAClient{
        endpoint: endpoint,
        httpClient: &http.Client{
            Timeout: 2 * time.Second,
        },
        logger: logger,
    }
}

func (o *OPAClient) Evaluate(ctx context.Context, input map[string]interface{}) (*Decision, error) {
    body, err := json.Marshal(map[string]interface{}{"input": input})
    if err != nil {
        return nil, fmt.Errorf("marshal OPA input: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodPost,
        o.endpoint+"/v1/data/firewall/decision", bytes.NewReader(body))
    if err != nil {
        return nil, fmt.Errorf("create OPA request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := o.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("OPA request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("OPA returned HTTP %d", resp.StatusCode)
    }

    var wrapper struct {
        Result Decision `json:"result"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
        return nil, fmt.Errorf("decode OPA response: %w", err)
    }

    o.logger.Info("opa decision",
        zap.Bool("allow", wrapper.Result.Allow),
        zap.String("reason", wrapper.Result.Reason),
    )

    return &wrapper.Result, nil
}
```

Wire it into `cmd/proxy/main.go` and `middleware.go`.

**ACCEPTANCE**:
```bash
# With OPA container running:
curl -X POST http://localhost:8181/v1/data/firewall/decision \
  -H "Content-Type: application/json" \
  -d '{"input":{"subject":{"has_roles":true,"roles":["nurse"],"fhir_context":{"department":"cardiology"}},"action":"GET","resource":{"type":"Patient"}}}'
# Should return {"result":{"allow":true,...}}
```

**FILES**: `internal/policy/opa_client.go` (new or complete), `cmd/proxy/main.go` (wire up)

---

### TASK 1.6 — Complete `internal/cache/revocation.go` and wire to middleware

**CONTEXT**:
Redis runs in Docker Compose at `redis:6379`. The revocation cache likely exists as a stub. Token revocation checking must happen after JWT validation and before OPA evaluation.

**TASK**:
Ensure `internal/cache/revocation.go` has:

```go
package cache

import (
    "context"
    "fmt"
    "time"

    "github.com/redis/go-redis/v9"
    "go.uber.org/zap"
)

type RevocationCache struct {
    client *redis.Client
    logger *zap.Logger
}

func NewRevocationCache(addr string, logger *zap.Logger) (*RevocationCache, error) {
    if addr == "" {
        return nil, nil // disabled, not an error
    }
    rdb := redis.NewClient(&redis.Options{Addr: addr})
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()
    if err := rdb.Ping(ctx).Err(); err != nil {
        return nil, fmt.Errorf("redis ping failed: %w", err)
    }
    logger.Info("redis connected", zap.String("addr", addr))
    return &RevocationCache{client: rdb, logger: logger}, nil
}

func (rc *RevocationCache) IsRevoked(ctx context.Context, tenantID, jti string) (bool, error) {
    key := fmt.Sprintf("revoke:%s:%s", tenantID, jti)
    exists, err := rc.client.Exists(ctx, key).Result()
    if err != nil {
        rc.logger.Error("revocation check failed", zap.Error(err))
        return false, nil // fail open
    }
    return exists > 0, nil
}

func (rc *RevocationCache) Revoke(ctx context.Context, tenantID, jti string, exp int64) error {
    ttl := time.Until(time.Unix(exp, 0))
    if ttl <= 0 {
        return nil
    }
    key := fmt.Sprintf("revoke:%s:%s", tenantID, jti)
    return rc.client.Set(ctx, key, "1", ttl).Err()
}
```

In middleware, after JWT validation and before OPA, add:
```go
if rc.cache != nil {
    revoked, _ := rc.cache.IsRevoked(r.Context(), tenantID, jti)
    if revoked {
        respondWithError(w, 401, "token_revoked", "Session has been terminated")
        return
    }
}
```

**ACCEPTANCE**:
```bash
# Manually revoke a JTI in Redis:
docker exec -it $(docker ps -qf name=redis) redis-cli SET "revoke:hospital-a:test-jti-123" "1" EX 900
# Then try to use a token with that JTI — should get 401 token_revoked
```

**FILES**: `internal/cache/revocation.go`, `internal/auth/middleware.go`

---

### TASK 1.7 — Implement the FHIR reverse proxy handler

**CONTEXT**:
`fhirProxyHandler` in `cmd/proxy/main.go` either writes a stub response or is not forwarding to the upstream FHIR server. The upstream URL comes from `FHIR_UPSTREAM` environment variable (default `http://fhir:8080/fhir`).

**TASK**:
Create `internal/proxy/fhir_handler.go`:

```go
package proxy

import (
    "encoding/json"
    "io"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strings"

    "go.uber.org/zap"

    "github.com/vikram290227/fhir-privacy-proxy/internal/auth"
    "github.com/vikram290227/fhir-privacy-proxy/internal/policy"
)

type FHIRHandler struct {
    upstream   *url.URL
    proxy      *httputil.ReverseProxy
    logger     *zap.Logger
}

func NewFHIRHandler(upstreamURL string, logger *zap.Logger) (*FHIRHandler, error) {
    u, err := url.Parse(upstreamURL)
    if err != nil {
        return nil, err
    }
    rp := httputil.NewSingleHostReverseProxy(u)
    rp.ModifyResponse = func(resp *http.Response) error {
        // Redaction is applied after OPA decision in the middleware
        return nil
    }
    return &FHIRHandler{upstream: u, proxy: rp, logger: logger}, nil
}

func (h *FHIRHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // Get OPA decision (set by middleware)
    decision, _ := r.Context().Value(policy.DecisionKey).(*policy.Decision)

    // Strip auth header before forwarding
    r.Header.Del("Authorization")
    r.Header.Del("X-Break-Glass")
    r.Header.Del("X-Break-Glass-Justification")

    // Add proxy identity header
    if sub, ok := r.Context().Value(auth.SubjectContextKey).(*auth.SubjectContext); ok {
        r.Header.Set("X-Proxy-Subject", sub.SubjectID)
        r.Header.Set("X-Proxy-Tenant", sub.TenantID)
    }

    // Rewrite path: /fhir/r4/* -> upstream path
    r.URL.Host = h.upstream.Host
    r.URL.Scheme = h.upstream.Scheme

    if decision == nil || decision.Allow {
        // Capture response for redaction
        rec := &responseRecorder{header: make(http.Header), statusCode: 200}
        h.proxy.ServeHTTP(rec, r)

        // Apply field-level redaction if OPA returned rules
        body := rec.body
        if decision != nil && (len(decision.Remove) > 0 || len(decision.Mask) > 0) {
            body = applyRedaction(body, decision.Remove, decision.Mask)
        }

        // Write final response
        for k, v := range rec.header {
            for _, vv := range v {
                w.Header().Add(k, vv)
            }
        }
        w.WriteHeader(rec.statusCode)
        w.Write(body)
    }
}
```

Implement `responseRecorder` (captures the upstream response body for redaction) and `applyRedaction` (walks the JSON and removes/masks specified JSON Pointer paths).

**ACCEPTANCE**:
```bash
TOKEN=$(./scripts/get_token.sh doctor1 password | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/fhir/r4/metadata
# Must return the HAPI FHIR CapabilityStatement JSON, not a stub
```

**FILES**: `internal/proxy/fhir_handler.go` (new), `internal/proxy/redaction.go` (new), `cmd/proxy/main.go` (wire up)

---

### TASK 1.8 — Implement field-level redaction (`internal/proxy/redaction.go`)

**CONTEXT**:
OPA returns `remove` and `mask` arrays of JSON Pointer paths (e.g. `"$.telecom"`, `"$.identifier[0].value"`). The proxy must apply these to the FHIR response body before returning it to the client. It must also handle FHIR Bundles (apply redaction to each `entry.resource`).

**TASK**:
```go
package proxy

import (
    "encoding/json"
    "strings"
)

// applyRedaction applies OPA-directed field removal and masking to a FHIR
// JSON response. It handles both individual resources and FHIR Bundles.
func applyRedaction(body []byte, remove, mask []string) []byte {
    if len(remove) == 0 && len(mask) == 0 {
        return body
    }

    var resource map[string]interface{}
    if err := json.Unmarshal(body, &resource); err != nil {
        return body // not JSON, return as-is
    }

    // Handle FHIR Bundle
    if rt, _ := resource["resourceType"].(string); rt == "Bundle" {
        if entries, ok := resource["entry"].([]interface{}); ok {
            for _, e := range entries {
                if entry, ok := e.(map[string]interface{}); ok {
                    if res, ok := entry["resource"].(map[string]interface{}); ok {
                        applyToResource(res, remove, mask)
                    }
                }
            }
        }
    } else {
        applyToResource(resource, remove, mask)
    }

    out, err := json.Marshal(resource)
    if err != nil {
        return body
    }
    return out
}

func applyToResource(res map[string]interface{}, remove, mask []string) {
    for _, path := range remove {
        deleteByPath(res, normalisePath(path))
    }
    for _, path := range mask {
        maskByPath(res, normalisePath(path))
    }
}

// normalisePath strips leading "$." from OPA JSON pointer paths
func normalisePath(path string) []string {
    path = strings.TrimPrefix(path, "$.")
    return strings.Split(path, ".")
}

func deleteByPath(obj map[string]interface{}, parts []string) {
    if len(parts) == 1 {
        delete(obj, parts[0])
        return
    }
    if child, ok := obj[parts[0]].(map[string]interface{}); ok {
        deleteByPath(child, parts[1:])
    }
}

func maskByPath(obj map[string]interface{}, parts []string) {
    if len(parts) == 1 {
        if _, exists := obj[parts[0]]; exists {
            obj[parts[0]] = "***REDACTED***"
        }
        return
    }
    if child, ok := obj[parts[0]].(map[string]interface{}); ok {
        maskByPath(child, parts[1:])
    }
}
```

Write unit tests covering: remove top-level field, mask nested field, Bundle redaction, non-JSON passthrough.

**ACCEPTANCE**:
```bash
go test ./internal/proxy/... -v -run TestRedaction
# All tests pass
```

**FILES**: `internal/proxy/redaction.go` (new), `internal/proxy/redaction_test.go` (new)

---

## PHASE 2 — ML RISK SCORING SERVICE (Build After Phase 1)

---

### TASK 2.1 — Complete `ml/` FastAPI service skeleton

**CONTEXT**:
The `ml/` directory exists (Python 12.2% of codebase). The Docker Compose likely references a `risk` service. The service must accept feature vectors and return risk scores.

**TASK**:
Ensure `ml/main.py` has a complete FastAPI application:

```python
# ml/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import numpy as np
import logging

logger = logging.getLogger("risk-service")
app = FastAPI(title="FHIR Risk Scoring Service", version="0.1.0")

class AccessRequest(BaseModel):
    subject_id: str
    tenant_id: str
    department: str
    role: str
    resource_type: str
    resource_path: str
    action: str  # GET, POST, PUT, DELETE
    hour_of_day: int          # 0-23
    day_of_week: int          # 0=Monday
    accesses_last_hour: int   # from Redis counter
    accesses_today: int
    is_typical_department: bool
    has_care_team_relation: bool
    is_break_glass: bool

class RiskResponse(BaseModel):
    risk_score: float         # 0.0 = safe, 1.0 = high risk
    confidence: float
    reason: str
    top_factors: List[str]

@app.get("/health")
def health():
    return {"status": "ok", "model": "rule-based-baseline"}

@app.post("/score", response_model=RiskResponse)
def score_access(req: AccessRequest) -> RiskResponse:
    """
    Phase 1: Rule-based scoring (no ML model yet).
    Returns deterministic risk scores based on known risk factors.
    Phase 2: Replace with trained XGBoost model.
    """
    risk = 0.0
    factors = []

    # Risk factor 1: After-hours access (10 PM – 5 AM)
    if req.hour_of_day >= 22 or req.hour_of_day <= 5:
        risk += 0.25
        factors.append("After-hours access")

    # Risk factor 2: Unusual access volume
    if req.accesses_last_hour > 50:
        risk += 0.30
        factors.append(f"High volume: {req.accesses_last_hour} accesses in last hour")
    elif req.accesses_last_hour > 20:
        risk += 0.15
        factors.append(f"Elevated volume: {req.accesses_last_hour} accesses in last hour")

    # Risk factor 3: Cross-department access without care team relation
    if not req.is_typical_department and not req.has_care_team_relation:
        risk += 0.25
        factors.append("Cross-department access without care team relation")

    # Risk factor 4: Break-glass raises visibility (not risk)
    if req.is_break_glass:
        # Break-glass is legitimate emergency — don't penalise
        # but flag for audit
        factors.append("Break-glass override active")

    # Risk factor 5: Weekend high-volume
    if req.day_of_week >= 5 and req.accesses_today > 30:
        risk += 0.10
        factors.append("High weekend access volume")

    risk = min(risk, 1.0)
    confidence = 0.70 if len(factors) > 0 else 0.90

    return RiskResponse(
        risk_score=round(risk, 3),
        confidence=confidence,
        reason="rule-based" if risk < 0.3 else "elevated-risk-pattern",
        top_factors=factors[:3],
    )
```

Create `ml/requirements.txt`:
```
fastapi==0.111.0
uvicorn==0.30.1
pydantic==2.7.1
numpy==1.26.4
scikit-learn==1.5.0
xgboost==2.0.3
shap==0.45.0
pandas==2.2.2
```

Create `ml/Dockerfile`:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**ACCEPTANCE**:
```bash
curl http://localhost:8000/health
# {"status":"ok","model":"rule-based-baseline"}

curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{"subject_id":"nurse1","tenant_id":"hospital-a","department":"cardiology","role":"nurse","resource_type":"Patient","resource_path":"/fhir/r4/Patient/1","action":"GET","hour_of_day":2,"day_of_week":1,"accesses_last_hour":60,"accesses_today":10,"is_typical_department":true,"has_care_team_relation":false,"is_break_glass":false}'
# risk_score should be > 0.3 (after hours + high volume)
```

**FILES**: `ml/main.py`, `ml/requirements.txt`, `ml/Dockerfile`

---

### TASK 2.2 — Wire ML risk scoring into the Go proxy middleware

**CONTEXT**:
The README mentions `ScoreRisk` middleware that calls `RISK_SERVICE_URL`. This call must happen after rate limiting and before OPA policy evaluation.

**TASK**:
Create `internal/risk/client.go`:

```go
package risk

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "go.uber.org/zap"

    "github.com/vikram290227/fhir-privacy-proxy/internal/auth"
)

type Client struct {
    endpoint   string
    httpClient *http.Client
    logger     *zap.Logger
}

type ScoreResponse struct {
    RiskScore  float64  `json:"risk_score"`
    Confidence float64  `json:"confidence"`
    Reason     string   `json:"reason"`
    TopFactors []string `json:"top_factors"`
}

func NewClient(endpoint string, logger *zap.Logger) *Client {
    if endpoint == "" {
        return nil // disabled
    }
    return &Client{
        endpoint:   endpoint,
        httpClient: &http.Client{Timeout: 500 * time.Millisecond},
        logger:     logger,
    }
}

func (c *Client) Score(ctx context.Context, sub *auth.SubjectContext, r *http.Request) (*ScoreResponse, error) {
    if c == nil {
        return &ScoreResponse{RiskScore: 0.0, Reason: "disabled"}, nil
    }

    payload := map[string]interface{}{
        "subject_id":              sub.SubjectID,
        "tenant_id":               sub.TenantID,
        "department":              sub.FHIRContext.Department,
        "role":                    sub.FHIRContext.Role,
        "resource_type":           "Patient",
        "resource_path":           r.URL.Path,
        "action":                  r.Method,
        "hour_of_day":             time.Now().Hour(),
        "day_of_week":             int(time.Now().Weekday()),
        "accesses_last_hour":      0,
        "accesses_today":          0,
        "is_typical_department":   true,
        "has_care_team_relation":  false,
        "is_break_glass":          sub.BreakGlass != nil && sub.BreakGlass.Enabled,
    }

    body, _ := json.Marshal(payload)
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/score", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        c.logger.Warn("risk service unavailable, defaulting to 0.0", zap.Error(err))
        return &ScoreResponse{RiskScore: 0.0, Reason: "service-unavailable"}, nil
    }
    defer resp.Body.Close()

    var score ScoreResponse
    if err := json.NewDecoder(resp.Body).Decode(&score); err != nil {
        return nil, fmt.Errorf("decode risk response: %w", err)
    }
    return &score, nil
}
```

Add `ScoreRisk` middleware to the chi router chain in `cmd/proxy/main.go`. The risk score must be attached to the request context so OPA can receive it as part of the input.

**ACCEPTANCE**:
```bash
# Risk score appears in audit logs for every request
grep "risk_score" logs/audit.log
```

**FILES**: `internal/risk/client.go` (new), `cmd/proxy/main.go` (wire up ScoreRisk middleware)

---

### TASK 2.3 — Build ML training pipeline (`ml/train.py`)

**CONTEXT**:
The rule-based scorer in Task 2.1 is the baseline. Once pilot hospital data is available, this script trains an XGBoost binary classifier.

**TASK**:
Create `ml/train.py`:

```python
# ml/train.py
"""
Training pipeline for the FHIR access risk model.
Usage:
  python train.py --data /path/to/audit_logs.csv --output model.json

CSV columns required:
  subject_id, tenant_id, hour_of_day, day_of_week,
  accesses_last_hour, accesses_today, is_typical_department,
  has_care_team_relation, is_break_glass, label (0=legitimate, 1=inappropriate)
"""
import argparse
import pandas as pd
import xgboost as xgb
import shap
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, classification_report
import json

FEATURE_COLS = [
    "hour_of_day", "day_of_week", "accesses_last_hour",
    "accesses_today", "is_typical_department",
    "has_care_team_relation", "is_break_glass",
]

def train(data_path: str, output_path: str):
    df = pd.read_csv(data_path)
    assert "label" in df.columns, "CSV must have a 'label' column (0 or 1)"

    X = df[FEATURE_COLS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = xgb.XGBClassifier(
        objective="binary:logistic",
        max_depth=6,
        learning_rate=0.1,
        n_estimators=200,
        scale_pos_weight=(y_train == 0).sum() / (y_train == 1).sum(),
        eval_metric="auc",
        early_stopping_rounds=20,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    y_prob = model.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_prob)
    print(f"AUC-ROC: {auc:.4f}")
    print(classification_report(y_test, (y_prob > 0.5).astype(int)))

    model.save_model(output_path)
    print(f"Model saved to {output_path}")

    # SHAP explainability
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_test[:100])
    shap.summary_plot(shap_values, X_test[:100], feature_names=FEATURE_COLS, show=False)
    print("SHAP summary generated")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--output", default="model.json")
    args = parser.parse_args()
    train(args.data, args.output)
```

Update `ml/main.py` to load `model.json` at startup if it exists, falling back to the rule-based scorer:

```python
# At top of ml/main.py
import os
import xgboost as xgb

MODEL_PATH = os.getenv("MODEL_PATH", "model.json")
model = None

@app.on_event("startup")
def load_model():
    global model
    if os.path.exists(MODEL_PATH):
        model = xgb.XGBClassifier()
        model.load_model(MODEL_PATH)
        logger.info(f"XGBoost model loaded from {MODEL_PATH}")
    else:
        logger.info("No model file found — using rule-based scorer")

# In the /score endpoint:
# if model is not None:
#   features = [[req.hour_of_day, req.day_of_week, ...]]
#   risk = float(model.predict_proba(features)[0][1])
# else:
#   (use rule-based logic)
```

**ACCEPTANCE**:
```bash
# Generate synthetic training data and train
python ml/generate_synthetic_data.py --samples 10000 --output synthetic_logs.csv
python ml/train.py --data synthetic_logs.csv --output ml/model.json
# Must print AUC-ROC > 0.70 on synthetic data
```

**FILES**: `ml/train.py` (new), `ml/generate_synthetic_data.py` (new), `ml/main.py` (update)

---

### TASK 2.4 — Create synthetic data generator (`ml/generate_synthetic_data.py`)

**CONTEXT**:
Before real hospital data is available, a synthetic dataset is needed to test the training pipeline and validate the model architecture.

**TASK**:
```python
# ml/generate_synthetic_data.py
"""
Generates synthetic FHIR access log data for ML model development.
Labels are deterministic: high-risk patterns → label=1, normal → label=0.
"""
import argparse
import pandas as pd
import numpy as np

def generate(n_samples: int, output_path: str, seed: int = 42):
    rng = np.random.default_rng(seed)
    n_normal = int(n_samples * 0.92)
    n_anomalous = n_samples - n_normal

    def normal_sample(n):
        return pd.DataFrame({
            "hour_of_day":             rng.integers(7, 19, n),
            "day_of_week":             rng.integers(0, 5, n),
            "accesses_last_hour":      rng.integers(1, 25, n),
            "accesses_today":          rng.integers(5, 80, n),
            "is_typical_department":   rng.choice([True, False], n, p=[0.9, 0.1]),
            "has_care_team_relation":  rng.choice([True, False], n, p=[0.7, 0.3]),
            "is_break_glass":          rng.choice([True, False], n, p=[0.02, 0.98]),
            "label": 0,
        })

    def anomalous_sample(n):
        return pd.DataFrame({
            "hour_of_day":             rng.choice([0,1,2,3,22,23], n),
            "day_of_week":             rng.integers(0, 7, n),
            "accesses_last_hour":      rng.integers(50, 200, n),
            "accesses_today":          rng.integers(100, 500, n),
            "is_typical_department":   rng.choice([True, False], n, p=[0.2, 0.8]),
            "has_care_team_relation":  rng.choice([True, False], n, p=[0.1, 0.9]),
            "is_break_glass":          np.zeros(n, dtype=bool),
            "label": 1,
        })

    df = pd.concat([normal_sample(n_normal), anomalous_sample(n_anomalous)], ignore_index=True)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} samples ({n_anomalous} anomalous) → {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=10000)
    parser.add_argument("--output", default="synthetic_logs.csv")
    args = parser.parse_args()
    generate(args.samples, args.output)
```

**ACCEPTANCE**:
```bash
python ml/generate_synthetic_data.py --samples 10000 --output /tmp/test.csv
# Generates 10000 rows, 800 anomalous (8%)
python ml/train.py --data /tmp/test.csv --output /tmp/model.json
# AUC-ROC >= 0.80
```

**FILES**: `ml/generate_synthetic_data.py` (new)

---

## PHASE 3 — OPA POLICIES (Complete After Phase 1)

---

### TASK 3.1 — Complete the base OPA policy (`policies/base/authz.rego`)

**CONTEXT**:
A base policy exists but may have syntax errors or incomplete logic. The policy package must be `firewall.decision` and return a `result` object.

**TASK**:
Ensure `policies/base/authz.rego` contains a complete, valid Rego policy:

```rego
package firewall.decision

import future.keywords.if
import future.keywords.in

# ─── defaults ──────────────────────────────────────────────
default allow     := false
default remove    := []
default mask      := []
default reason    := "default-deny"

# ─── allow: normal clinical access ────────────────────────
allow if {
    input.subject.has_roles
    count(input.subject.roles) > 0
    valid_role_for_resource
    not is_sensitive_patient
}

# allow: break-glass override
allow if {
    input.subject.break_glass.enabled
    "can_break_glass" in input.subject.roles
    input.subject.has_roles
}

# allow: admin always has access
allow if {
    "admin" in input.subject.roles
}

# ─── role-resource rules ───────────────────────────────────
valid_role_for_resource if {
    "nurse" in input.subject.roles
    input.resource.type in {"Patient", "Observation", "Condition", "MedicationRequest", "AllergyIntolerance"}
}

valid_role_for_resource if {
    "doctor" in input.subject.roles
}

# ─── sensitive patient protection ─────────────────────────
is_sensitive_patient if {
    sp := data.sensitive_patients[input.subject.tenant_id]
    input.resource.id in sp
}

# ─── field redaction rules ─────────────────────────────────
remove := ["$.telecom"] if {
    input.resource.type == "Patient"
    "nurse" in input.subject.roles
    not "admin" in input.subject.roles
    input.subject.fhir_context.department != "ED"
    not input.subject.break_glass.enabled
}

mask := ["$.identifier[0].value"] if {
    input.resource.type == "Patient"
    not "admin" in input.subject.roles
}

# ─── reason ───────────────────────────────────────────────
reason := "authorized" if { allow }
reason := "no-roles" if { not input.subject.has_roles }
reason := "insufficient-role" if {
    input.subject.has_roles
    not valid_role_for_resource
}
reason := "sensitive-patient" if {
    valid_role_for_resource
    is_sensitive_patient
}
reason := "break-glass-access" if {
    input.subject.break_glass.enabled
    allow
}

# ─── final result object ──────────────────────────────────
result := {
    "allow":  allow,
    "remove": remove,
    "mask":   mask,
    "reason": reason,
}
```

**ACCEPTANCE**:
```bash
# Test with OPA CLI
opa eval \
  --input tests/opa/nurse_normal_input.json \
  --data policies/base/authz.rego \
  "data.firewall.decision.result"
# Must return {"allow":true,"remove":["$.telecom"],...}

opa eval \
  --input tests/opa/no_roles_input.json \
  --data policies/base/authz.rego \
  "data.firewall.decision.result"
# Must return {"allow":false,"reason":"no-roles",...}
```

Create test input files at `tests/opa/`:
- `nurse_normal_input.json`
- `no_roles_input.json`
- `break_glass_input.json`
- `sensitive_patient_input.json`

**FILES**: `policies/base/authz.rego`, `tests/opa/*.json`

---

### TASK 3.2 — Add OPA policy unit tests (`policies/base/authz_test.rego`)

**CONTEXT**:
OPA supports native unit tests using the `test_` prefix convention.

**TASK**:
```rego
# policies/base/authz_test.rego
package firewall.decision

import future.keywords.if

# Test: nurse with correct role and department gets access
test_nurse_allow if {
    result.allow == true with input as {
        "subject": {
            "has_roles": true,
            "roles": ["nurse"],
            "fhir_context": {"department": "cardiology"},
            "break_glass": {"enabled": false}
        },
        "resource": {"type": "Patient", "id": "patient-1"},
        "action": "GET"
    }
}

# Test: no roles → deny
test_no_roles_deny if {
    result.allow == false with input as {
        "subject": {
            "has_roles": false,
            "roles": [],
            "fhir_context": {"department": "cardiology"},
            "break_glass": {"enabled": false}
        },
        "resource": {"type": "Patient", "id": "patient-1"},
        "action": "GET"
    }
}

# Test: break-glass → allow
test_break_glass_allow if {
    result.allow == true with input as {
        "subject": {
            "has_roles": true,
            "roles": ["nurse", "can_break_glass"],
            "fhir_context": {"department": "cardiology"},
            "break_glass": {"enabled": true, "justification": "Emergency trauma"}
        },
        "resource": {"type": "Patient", "id": "patient-1"},
        "action": "GET"
    }
}

# Test: nurse gets telecom removed outside ED
test_nurse_telecom_removed if {
    result.remove == ["$.telecom"] with input as {
        "subject": {
            "has_roles": true,
            "roles": ["nurse"],
            "fhir_context": {"department": "cardiology"},
            "break_glass": {"enabled": false}
        },
        "resource": {"type": "Patient", "id": "patient-1"},
        "action": "GET"
    }
}
```

**ACCEPTANCE**:
```bash
opa test policies/ -v
# All tests pass, zero failures
```

**FILES**: `policies/base/authz_test.rego`

---

## PHASE 4 — OBSERVABILITY AND OPERATIONS

---

### TASK 4.1 — Complete structured audit logging to file and Azure Blob

**CONTEXT**:
`go.uber.org/zap` is used for logging. Audit events are written to stdout. Azure Blob Storage sink is mentioned in the README but may not be fully implemented. Azure credentials come from environment variables `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_KEY`, `AZURE_AUDIT_CONTAINER`.

**TASK**:
Create `internal/audit/logger.go` with two sinks: stdout (always) and Azure Blob (optional):

```go
package audit

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "time"

    "go.uber.org/zap"
)

type Event struct {
    Timestamp   time.Time              `json:"timestamp"`
    EventType   string                 `json:"event_type"`
    TenantID    string                 `json:"tenant_id"`
    Decision    string                 `json:"decision"`   // allow | deny
    Reason      string                 `json:"reason"`
    Severity    string                 `json:"severity"`   // INFO | CRITICAL
    SubjectID   string                 `json:"subject_id"`
    Department  string                 `json:"department"`
    Roles       []string               `json:"roles"`
    ResourceType string               `json:"resource_type"`
    ResourcePath string               `json:"resource_path"`
    Action      string                 `json:"action"`
    RiskScore   float64               `json:"risk_score"`
    BreakGlass  bool                  `json:"break_glass"`
    Justification string              `json:"justification,omitempty"`
    SessionID   string                 `json:"session_id"`
    ClientIP    string                 `json:"client_ip"`
    LatencyMs   int64                  `json:"latency_ms"`
    HTTPStatus  int                   `json:"http_status"`
}

type Logger struct {
    zap   *zap.Logger
    azure *azureSink // nil if not configured
}

func New(zapLogger *zap.Logger) *Logger {
    l := &Logger{zap: zapLogger}
    acct := os.Getenv("AZURE_STORAGE_ACCOUNT")
    key  := os.Getenv("AZURE_STORAGE_KEY")
    cont := os.Getenv("AZURE_AUDIT_CONTAINER")
    if acct != "" && key != "" && cont != "" {
        sink, err := newAzureSink(acct, key, cont)
        if err != nil {
            zapLogger.Warn("azure audit sink disabled", zap.Error(err))
        } else {
            l.azure = sink
            zapLogger.Info("azure audit sink enabled", zap.String("container", cont))
        }
    }
    return l
}

func (l *Logger) Log(ctx context.Context, ev Event) {
    ev.Timestamp = time.Now().UTC()
    if ev.BreakGlass {
        ev.Severity = "CRITICAL"
        ev.EventType = "break_glass_access"
    } else if ev.EventType == "" {
        ev.EventType = "access_decision"
        ev.Severity = "INFO"
    }

    // Always log to stdout (structured JSON)
    data, _ := json.Marshal(ev)
    l.zap.Info(string(data),
        zap.String("event_type", ev.EventType),
        zap.String("tenant", ev.TenantID),
        zap.String("subject", ev.SubjectID),
        zap.String("decision", ev.Decision),
        zap.Float64("risk_score", ev.RiskScore),
    )

    // Optionally ship to Azure Blob
    if l.azure != nil {
        go func() {
            if err := l.azure.write(ctx, ev); err != nil {
                l.zap.Error("azure audit write failed", zap.Error(err))
            }
        }()
    }
}
```

The `azureSink` must write one JSON object per line to a blob named `YYYY/MM/DD/HH-<uuid>.jsonl`.

**ACCEPTANCE**:
```bash
TOKEN=$(./scripts/get_token.sh nurse1 password | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/fhir/r4/Patient/test
# Inspect logs:
docker logs $(docker ps -qf name=proxy) 2>&1 | grep "event_type" | jq .
# Must show structured audit event with all required fields
```

**FILES**: `internal/audit/logger.go` (new or complete), `internal/audit/azure_sink.go` (new)

---

### TASK 4.2 — Add Prometheus metrics to all middleware stages

**CONTEXT**:
The README mentions a Prometheus `/metrics` endpoint and Grafana dashboard. The proxy may have basic metrics but likely lacks per-stage instrumentation.

**TASK**:
Create `internal/metrics/metrics.go`:

```go
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
    RequestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "fhir_proxy_requests_total"},
        []string{"tenant", "method", "resource_type", "decision"},
    )

    RequestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "fhir_proxy_request_duration_seconds",
            Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5},
        },
        []string{"tenant", "stage"}, // stages: jwt, opa, upstream
    )

    RiskScoreHistogram = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "fhir_proxy_risk_score",
        Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
    })

    BreakGlassTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "fhir_proxy_break_glass_total"},
        []string{"tenant", "subject"},
    )

    RateLimitHits = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "fhir_proxy_rate_limit_hits_total"},
        []string{"tenant", "subject", "window"},
    )

    AuthFailures = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "fhir_proxy_auth_failures_total"},
        []string{"tenant", "reason"},
    )

    JWKSCacheHits = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "fhir_proxy_jwks_cache_total"},
        []string{"tenant", "result"}, // result: hit | miss
    )
)

func Register() {
    prometheus.MustRegister(
        RequestsTotal, RequestDuration, RiskScoreHistogram,
        BreakGlassTotal, RateLimitHits, AuthFailures, JWKSCacheHits,
    )
}
```

Instrument every middleware stage using these counters. Ensure the Grafana dashboard in `deployments/` matches these metric names.

**ACCEPTANCE**:
```bash
curl http://localhost:8080/metrics | grep fhir_proxy_requests_total
# Must show non-zero counter after sending test requests
```

**FILES**: `internal/metrics/metrics.go` (new), instrument all middleware files

---

### TASK 4.3 — Complete OpenTelemetry tracing across all stages

**CONTEXT**:
OpenTelemetry is imported (`go.opentelemetry.io/otel`) and Jaeger runs at port 16686. Tracing may be configured but individual middleware stages may lack spans.

**TASK**:
Ensure every stage in the request pipeline creates a child span:

```go
// Pattern for each middleware
ctx, span := otel.Tracer("fhir-proxy").Start(r.Context(), "ValidateToken")
defer span.End()

// Add key attributes
span.SetAttributes(
    attribute.String("tenant_id", tenantID),
    attribute.String("subject_id", subjectID),
)

// On error
span.RecordError(err)
span.SetStatus(codes.Error, err.Error())
```

Stages to instrument:
- `ValidateToken`
- `RevocationCheck`
- `ScopeValidation`
- `RateLimit`
- `ScoreRisk`
- `EnforcePolicy`
- `UpstreamProxy`
- `ApplyRedaction`

**ACCEPTANCE**:
```bash
# Send a request, then check Jaeger
open http://localhost:16686
# Search service: fhir-privacy-proxy
# Should see a trace with all 8 spans
```

**FILES**: All middleware files in `internal/auth/`, `internal/policy/`, `internal/proxy/`

---

## PHASE 5 — TESTING

---

### TASK 5.1 — Unit test suite (minimum 80% coverage)

**CONTEXT**:
No test files confirmed in the repository. Tests are required for all core logic.

**TASK**:
Create the following test files:

```
internal/auth/jwt_validator_test.go    — test ValidateToken with mock JWKS
internal/auth/context_builder_test.go — test claim extraction edge cases
internal/tenant/registry_test.go      — test YAML loading
internal/proxy/redaction_test.go      — test remove/mask/bundle redaction
internal/cache/revocation_test.go     — test Redis revocation (use miniredis)
internal/policy/opa_client_test.go    — test OPA HTTP client with mock server
```

For JWT tests, generate a test RSA key pair and self-sign tokens:

```go
// internal/auth/testhelpers_test.go
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    require.NoError(t, err)
    return key, &key.PublicKey
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    token.Header["kid"] = "test-key-id"
    signed, err := token.SignedString(key)
    require.NoError(t, err)
    return signed
}
```

**ACCEPTANCE**:
```bash
go test ./... -v -coverprofile=coverage.out
go tool cover -func=coverage.out | grep total
# Must show >= 80% total coverage
```

**FILES**: All test files listed above

---

### TASK 5.2 — Integration test script (`scripts/integration_test.sh`)

**CONTEXT**:
`scripts/test_patient.sh` and `scripts/test_smart_launch.sh` exist. A comprehensive integration test covering all scenarios is needed.

**TASK**:
Create `scripts/integration_test.sh`:

```bash
#!/bin/bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
PASS=0
FAIL=0

check() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [ "$actual" = "$expected" ]; then
        echo "  ✅ $desc"
        PASS=$((PASS+1))
    else
        echo "  ❌ $desc (expected=$expected, got=$actual)"
        FAIL=$((FAIL+1))
    fi
}

echo "=== Health Check ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health")
check "GET /health returns 200" "200" "$STATUS"

echo "=== No Token ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/fhir/r4/Patient/1")
check "No token returns 401" "401" "$STATUS"

echo "=== Invalid Token ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer invalid.token.here" \
  "$BASE_URL/fhir/r4/Patient/1")
check "Bad token returns 401" "401" "$STATUS"

echo "=== Nurse Access ==="
TOKEN=$(./scripts/get_token.sh nurse1 password | jq -r .access_token)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/fhir/r4/Patient/test-patient-1")
check "Nurse access returns 200 or 404 (not 401/403)" "200|404" "$(echo $STATUS | grep -cP '200|404' || echo $STATUS)"

echo "=== Telecom Redaction (nurse outside ED) ==="
BODY=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/fhir/r4/Patient/test-patient-1")
HAS_TELECOM=$(echo "$BODY" | jq 'has("telecom")' 2>/dev/null || echo "error")
check "Nurse response has no telecom field" "false" "$HAS_TELECOM"

echo "=== Break-Glass without header ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Break-Glass: true" \
  "$BASE_URL/fhir/r4/Patient/test-patient-1")
# nurse1 has can_break_glass role but needs justification
check "Break-glass without justification returns 400" "400" "$STATUS"

echo "=== Break-Glass with valid header ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Break-Glass: true" \
  -H "X-Break-Glass-Justification: Patient arrived unconscious in ER, need medication history" \
  "$BASE_URL/fhir/r4/Patient/test-patient-1")
check "Valid break-glass returns 200 or 404" "200|404" "$(echo $STATUS | grep -cP '200|404' || echo $STATUS)"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && exit 0 || exit 1
```

**ACCEPTANCE**:
```bash
make up
sleep 30
bash scripts/integration_test.sh
# Must show: X passed, 0 failed
```

**FILES**: `scripts/integration_test.sh` (new)

---

## PHASE 6 — PRODUCTION READINESS

---

### TASK 6.1 — Kubernetes Helm chart (`deployments/helm/`)

**CONTEXT**:
Only Docker Compose exists. Production deployment requires Kubernetes.

**TASK**:
Create a minimal Helm chart at `deployments/helm/fhir-privacy-proxy/`:

```
deployments/helm/fhir-privacy-proxy/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── hpa.yaml              # HorizontalPodAutoscaler
│   ├── servicemonitor.yaml   # Prometheus ServiceMonitor
│   └── ingress.yaml
```

Key `values.yaml` settings:
```yaml
replicaCount: 2
image:
  repository: ghcr.io/vikram290227/fhir-privacy-proxy
  tag: latest
resources:
  requests:
    cpu: 500m
    memory: 256Mi
  limits:
    cpu: 2000m
    memory: 1Gi
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
env:
  OPA_URL: "http://opa:8181"
  FHIR_UPSTREAM: "http://fhir-server/fhir"
  REDIS_ADDR: ""
  RISK_SERVICE_URL: ""
secrets:
  AZURE_STORAGE_ACCOUNT: ""
  AZURE_STORAGE_KEY: ""
```

**ACCEPTANCE**:
```bash
helm lint deployments/helm/fhir-privacy-proxy/
helm template deployments/helm/fhir-privacy-proxy/ | kubectl apply --dry-run=client -f -
# Both must succeed with 0 errors
```

**FILES**: Full Helm chart under `deployments/helm/`

---

### TASK 6.2 — GitHub Actions CI/CD pipeline

**CONTEXT**:
`.github/workflows/` exists but pipeline may not run tests, build Docker images, or push to registry.

**TASK**:
Ensure `.github/workflows/ci.yml` does:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: go build
        run: go build ./...
      - name: go vet
        run: go vet ./...
      - name: go test
        run: go test ./... -coverprofile=coverage.out
      - name: coverage check
        run: |
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | tr -d '%')
          echo "Coverage: $COVERAGE%"
          awk "BEGIN{ if ($COVERAGE < 80) exit 1 }"
      - name: opa lint
        uses: open-policy-agent/setup-opa@v2
      - run: opa test policies/ -v

  docker:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/vikram290227/fhir-privacy-proxy:latest
```

**ACCEPTANCE**:
```
Push to main → GitHub Actions passes all jobs → Docker image pushed to ghcr.io
```

**FILES**: `.github/workflows/ci.yml`

---

### TASK 6.3 — Graceful shutdown and health check improvements

**CONTEXT**:
`/health` returns `200 OK` but doesn't check dependencies. Kubernetes liveness and readiness probes need meaningful responses.

**TASK**:
Update the health endpoint:

```go
// GET /health/live — liveness: is the process running?
r.Get("/health/live", func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "live"})
})

// GET /health/ready — readiness: can we serve traffic?
r.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
    deps := checkDependencies(r.Context(), opaClient, redisClient, fhirUpstream)
    allOK := true
    for _, d := range deps {
        if d.Status == "error" {
            allOK = false
        }
    }
    if allOK {
        w.WriteHeader(http.StatusOK)
    } else {
        w.WriteHeader(http.StatusServiceUnavailable)
    }
    json.NewEncoder(w).Encode(map[string]interface{}{"dependencies": deps})
})
```

**ACCEPTANCE**:
```bash
curl http://localhost:8080/health/ready
# {"dependencies":[{"name":"opa","status":"ok"},{"name":"redis","status":"ok"},{"name":"fhir","status":"ok"}]}
```

**FILES**: `cmd/proxy/main.go`

---

## PHASE 7 — PRIVACY OFFICER DASHBOARD (Final Phase)

---

### TASK 7.1 — Privacy Officer web dashboard (React SPA)

**CONTEXT**:
A `demo-app/` exists for the SMART-on-FHIR demo. A separate Privacy Officer dashboard is needed for reviewing flagged access events and break-glass incidents.

**TASK**:
Create `dashboard/` with a minimal React application:

```
dashboard/
├── package.json
├── index.html
├── src/
│   ├── App.jsx
│   ├── components/
│   │   ├── EventTable.jsx      # Paginated list of audit events
│   │   ├── EventDetail.jsx     # Full event detail with SHAP factors
│   │   ├── BreakGlassAlert.jsx # Critical events highlighted
│   │   └── StatsCards.jsx      # Today's metrics (total, denied, break-glass)
│   └── api.js                  # Calls to /admin/v1/audit/tail
```

The dashboard uses the existing Admin API (`/admin/v1/audit/tail`) to fetch events. No new backend is needed for MVP.

Features required:
- Show last 100 audit events in a table (timestamp, user, department, patient, decision, risk score)
- Highlight CRITICAL (break-glass) events in red
- Filter by: tenant, decision (allow/deny), severity
- Click row to expand full event JSON
- Auto-refresh every 30 seconds
- Export to CSV button

**ACCEPTANCE**:
```bash
cd dashboard && npm install && npm run dev
# Opens at http://localhost:5173
# Must show real audit events from the running proxy
```

**FILES**: Full `dashboard/` React application

---

## VERIFICATION CHECKLIST

Run this after completing all phases to confirm the application is fully working:

```bash
# 1. Everything builds
go build ./...

# 2. All Go tests pass with ≥80% coverage
go test ./... -cover

# 3. OPA policies pass their tests
opa test policies/ -v

# 4. Full stack starts
make up
sleep 30
curl http://localhost:8080/health/ready

# 5. ML service is up
curl http://localhost:8000/health

# 6. Integration test suite passes
bash scripts/integration_test.sh

# 7. A real FHIR request flows end-to-end
TOKEN=$(./scripts/get_token.sh doctor1 password | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/fhir/r4/metadata | jq .resourceType
# Must print "CapabilityStatement"

# 8. Audit log contains structured events
docker logs $(docker ps -qf name=proxy) 2>&1 | grep event_type | tail -5 | jq .

# 9. Prometheus metrics visible
curl -s http://localhost:8080/metrics | grep fhir_proxy_requests_total

# 10. Jaeger trace exists
open http://localhost:16686
# Search service=fhir-privacy-proxy, verify spans present

# 11. Grafana dashboard loads
open http://localhost:3000
# Default login: admin/admin, find "FHIR Privacy Proxy" dashboard

# 12. Break-glass end-to-end
TOKEN=$(./scripts/get_token.sh nurse1 password | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "X-Break-Glass: true" \
  -H "X-Break-Glass-Justification: Integration test - patient arrived unconscious no records" \
  http://localhost:8080/fhir/r4/Patient/emergency-patient-1
# Must return 200 (not 401 or 403)
```

---

## SUMMARY: TASK PRIORITY ORDER

| Phase | Tasks | Priority | Estimated Hours |
|-------|-------|----------|----------------|
| Phase 1 — Stability | 1.1 → 1.8 | 🔴 Critical (do first) | 24h |
| Phase 3 — OPA Policies | 3.1 → 3.2 | 🔴 Critical | 4h |
| Phase 5 — Testing | 5.1 → 5.2 | 🟠 High | 8h |
| Phase 2 — ML Service | 2.1 → 2.4 | 🟠 High | 12h |
| Phase 4 — Observability | 4.1 → 4.3 | 🟡 Medium | 6h |
| Phase 6 — Prod Readiness | 6.1 → 6.3 | 🟡 Medium | 8h |
| Phase 7 — Dashboard | 7.1 | 🟢 Nice-to-have | 16h |
| **Total** | | | **~78 hours** |

---

*Last updated: May 2026*
*Repository: https://github.com/vikram290227/fhir-privacy-proxy*