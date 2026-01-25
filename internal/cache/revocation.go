package cache

import (
	"context"
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

func (rc *RevocationCache) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement Keycloak webhook handler
	w.WriteHeader(http.StatusAccepted)
}
