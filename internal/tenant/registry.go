package tenant

import (
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	IssuerURL        string        `yaml:"issuer_url"`
	TenantID         string        `yaml:"tenant_id"`
	JWKSEndpoint     string        `yaml:"jwks_endpoint"`
	Audience         string        `yaml:"audience"`
	PolicyBundle     string        `yaml:"policy_bundle"`
	TokenTTL         time.Duration `yaml:"token_ttl"`
	AllowedScopes    []string      `yaml:"allowed_scopes"`
	RevocationPrefix string        `yaml:"revocation_prefix"`
}

type Registry struct {
	tenants map[string]*Config
	mu      sync.RWMutex
}

type registryFile struct {
	Tenants []Config `yaml:"tenants"`
}

func LoadRegistry(configPath string) (*Registry, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading tenant config: %w", err)
	}

	var file registryFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing tenant config: %w", err)
	}

	tenants := make(map[string]*Config, len(file.Tenants))
	for i := range file.Tenants {
		t := &file.Tenants[i]
		if t.TokenTTL == 0 {
			t.TokenTTL = 15 * time.Minute
		}
		tenants[t.IssuerURL] = t
	}

	return &Registry{tenants: tenants}, nil
}

func (r *Registry) GetAll() map[string]*Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tenants
}

func (r *Registry) GetByIssuer(issuer string) (*Config, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tenant, ok := r.tenants[issuer]
	if !ok {
		return nil, fmt.Errorf("unknown issuer: %s", issuer)
	}

	return tenant, nil
}
