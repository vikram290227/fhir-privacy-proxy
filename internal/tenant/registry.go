package tenant

import (
	"fmt"
	"sync"
	"time"
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

func LoadRegistry(configPath string) (*Registry, error) {
	// TODO: Load from YAML file
	// For now, return a mock registry
	return &Registry{
		tenants: map[string]*Config{
			"https://hospital-a.keycloak.local/realms/main": {
				IssuerURL:    "https://hospital-a.keycloak.local/realms/main",
				TenantID:     "hospital-a",
				JWKSEndpoint: "https://hospital-a.keycloak.local/realms/main/protocol/openid-connect/certs",
				Audience:     "fhir-privacy-proxy",
				PolicyBundle: "hospital-a",
				TokenTTL:     15 * time.Minute,
			},
		},
	}, nil
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
