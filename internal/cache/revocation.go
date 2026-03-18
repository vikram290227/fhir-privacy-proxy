package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type RevocationCache struct {
	redis  *redis.Client
	logger *zap.Logger
}

func NewRevocationCache(addr string, logger *zap.Logger) *RevocationCache {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: "",
		DB:       0,
	})

	return &RevocationCache{
		redis:  rdb,
		logger: logger,
	}
}

// Ping checks connectivity to Redis. Returns nil if Redis is reachable.
func (rc *RevocationCache) Ping(ctx context.Context) error {
	return rc.redis.Ping(ctx).Err()
}

func (rc *RevocationCache) IsRevoked(tenantID, jti string, exp int64) (bool, error) {
	key := fmt.Sprintf("revoke:%s:%s", tenantID, jti)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	exists, err := rc.redis.Exists(ctx, key).Result()
	if err != nil {
		rc.logger.Error("revocation cache check failed", zap.Error(err))
		return false, err
	}

	return exists > 0, nil
}

func (rc *RevocationCache) Revoke(tenantID, jti string, exp int64) error {
	key := fmt.Sprintf("revoke:%s:%s", tenantID, jti)

	ttl := time.Until(time.Unix(exp, 0))
	if ttl < 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	return rc.redis.Set(ctx, key, "1", ttl).Err()
}

// keycloakEvent represents a Keycloak admin event for token revocation.
type keycloakEvent struct {
	Type         string `json:"type"`
	RealmID      string `json:"realmId"`
	ResourceType string `json:"resourceType"`
	ResourcePath string `json:"resourcePath"`
	Details      struct {
		TokenID  string `json:"token_id"`
		UserID   string `json:"user_id"`
		ClientID string `json:"client_id"`
		Exp      int64  `json:"exp"`
	} `json:"details"`
}

// HandleWebhook processes Keycloak logout/revocation webhook events.
// It expects a JSON body with token revocation details and adds
// the revoked token to the Redis cache.
func (rc *RevocationCache) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var event keycloakEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		rc.logger.Warn("invalid webhook payload", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid payload"})
		return
	}

	// Only process token revocation events
	if event.Type != "LOGOUT" && event.Type != "REVOKE_TOKEN" && event.Type != "LOGOUT_ERROR" {
		rc.logger.Debug("ignoring non-revocation event", zap.String("type", event.Type))
		w.WriteHeader(http.StatusAccepted)
		return
	}

	tokenID := event.Details.TokenID
	if tokenID == "" {
		rc.logger.Warn("webhook event missing token_id")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing token_id"})
		return
	}

	tenantID := event.RealmID
	if tenantID == "" {
		tenantID = "default"
	}

	exp := event.Details.Exp
	if exp == 0 {
		// Default: revoke for 1 hour if no expiry provided
		exp = time.Now().Add(1 * time.Hour).Unix()
	}

	if err := rc.Revoke(tenantID, tokenID, exp); err != nil {
		rc.logger.Error("failed to revoke token via webhook",
			zap.String("token_id", tokenID),
			zap.String("tenant_id", tenantID),
			zap.Error(err))
		http.Error(w, "revocation failed", http.StatusInternalServerError)
		return
	}

	rc.logger.Info("token revoked via webhook",
		zap.String("token_id", tokenID),
		zap.String("tenant_id", tenantID),
		zap.String("event_type", event.Type))

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}
