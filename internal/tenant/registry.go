package tenant

import (
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config describes an individual tenant's trust and policy settings.
// Each tenant is strictly isolated: their JWKS, scope list, OPA data
// file, and policy bundle are looked up via the issuer_url.
type Config struct {
	IssuerURL        string        `yaml:"issuer_url"`
	TenantID         string        `yaml:"tenant_id"`
	JWKSEndpoint     string        `yaml:"jwks_endpoint"`
	Audience         string        `yaml:"audience"`
	PolicyBundle     string        `yaml:"policy_bundle"`
	PolicyVersion    string        `yaml:"policy_version"`
	TokenTTL         time.Duration `yaml:"token_ttl"`
	AllowedScopes    []string      `yaml:"allowed_scopes"`
	RevocationPrefix string        `yaml:"revocation_prefix"`
	// OPADataPath is the per-tenant OPA data file (merged into
	// data.<tenant_id> inside OPA). Empty means the tenant relies on
	// the global data.json.
	OPADataPath string `yaml:"opa_data_path"`
	// SensitivePatients is a per-tenant allow-list of patient ids that
	// require break-glass / admin to access. Loaded in-process and
	// passed to OPA via the request input.
	SensitivePatients []string `yaml:"sensitive_patients"`
}

// Registry holds all tenants keyed by issuer URL and by tenant_id for
// fast isolated lookup.
type Registry struct {
	byIssuer map[string]*Config
	byID     map[string]*Config
	mu       sync.RWMutex
}

type registryFile struct {
	Tenants []Config `yaml:"tenants"`
}

// LoadRegistry reads the tenant YAML and returns an isolated registry.
func LoadRegistry(configPath string) (*Registry, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading tenant config: %w", err)
	}

	var file registryFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing tenant config: %w", err)
	}

	byIssuer := make(map[string]*Config, len(file.Tenants))
	byID := make(map[string]*Config, len(file.Tenants))
	for i := range file.Tenants {
		t := &file.Tenants[i]
		if t.TokenTTL == 0 {
			t.TokenTTL = 15 * time.Minute
		}
		if t.PolicyVersion == "" {
			t.PolicyVersion = "v1"
		}
		if t.IssuerURL == "" || t.TenantID == "" {
			return nil, fmt.Errorf("tenant %d: issuer_url and tenant_id required", i)
		}
		if _, exists := byIssuer[t.IssuerURL]; exists {
			return nil, fmt.Errorf("duplicate issuer_url: %s", t.IssuerURL)
		}
		if _, exists := byID[t.TenantID]; exists {
			return nil, fmt.Errorf("duplicate tenant_id: %s", t.TenantID)
		}
		byIssuer[t.IssuerURL] = t
		byID[t.TenantID] = t
	}

	return &Registry{byIssuer: byIssuer, byID: byID}, nil
}

// GetAll returns a snapshot map of issuer->Config. The returned map
// shares pointers with the registry; callers must not mutate values.
func (r *Registry) GetAll() map[string]*Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]*Config, len(r.byIssuer))
	for k, v := range r.byIssuer {
		out[k] = v
	}
	return out
}

// GetByIssuer looks up a tenant by OIDC issuer URL. The isolation
// invariant is enforced here: callers only ever get back the config
// for the tenant that owns the issuer.
func (r *Registry) GetByIssuer(issuer string) (*Config, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tenant, ok := r.byIssuer[issuer]
	if !ok {
		return nil, fmt.Errorf("unknown issuer: %s", issuer)
	}

	return tenant, nil
}

// GetByID returns the tenant config whose tenant_id matches id.
func (r *Registry) GetByID(id string) (*Config, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("unknown tenant: %s", id)
	}
	return t, nil
}
