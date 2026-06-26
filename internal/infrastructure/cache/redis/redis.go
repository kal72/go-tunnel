package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	domainTunnel "gotunnel/internal/domain/tunnel"

	"github.com/redis/go-redis/v9"
)

type TunnelRedisStore struct {
	client     *redis.Client
	prefix     string
	authPrefix string
	domainKey  string
}

func NewTunnelRedisStore(addr, pass string, db int) *TunnelRedisStore {
	return &TunnelRedisStore{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: pass,
			DB:       db,
		}),
		prefix:     "tunnel:",
		authPrefix: "auth:",
		domainKey:  "allowed_domains",
	}
}

func (s *TunnelRedisStore) Ping(ctx context.Context) {
	pong, err := s.client.Ping(ctx).Result()
	if err != nil {
		fmt.Println("Redis connection failed:", err)
		return
	}

	fmt.Println("Redis connected:", pong)
}

func (s *TunnelRedisStore) SetTunnel(ctx context.Context, sessionID string, info domainTunnel.TunnelInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	// Expire after 1 hour if not refreshed
	return s.client.Set(ctx, s.prefix+sessionID, data, 1*time.Hour).Err()
}

func (s *TunnelRedisStore) DeleteTunnel(ctx context.Context, sessionID string) error {
	return s.client.Del(ctx, s.prefix+sessionID).Err()
}

func (s *TunnelRedisStore) ListTunnels(ctx context.Context) ([]domainTunnel.TunnelInfo, error) {
	keys, err := s.client.Keys(ctx, s.prefix+"*").Result()
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return []domainTunnel.TunnelInfo{}, nil
	}

	var infos []domainTunnel.TunnelInfo
	for _, key := range keys {
		data, err := s.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		var info domainTunnel.TunnelInfo
		if err := json.Unmarshal([]byte(data), &info); err == nil {
			infos = append(infos, info)
		}
	}
	return infos, nil
}

func (s *TunnelRedisStore) SetToken(ctx context.Context, token string, expiration time.Duration) error {
	return s.client.Set(ctx, s.authPrefix+token, "valid", expiration).Err()
}

func (s *TunnelRedisStore) IsTokenRevoked(ctx context.Context, token string) (bool, error) {
	val, err := s.client.Get(ctx, s.authPrefix+token).Result()
	if errors.Is(err, redis.Nil) {
		return true, nil // If not in redis, consider it revoked or expired
	}
	if err != nil {
		return false, err
	}
	return val == "revoked", nil
}

func (s *TunnelRedisStore) RevokeToken(ctx context.Context, token string) error {
	// We could either delete it or set it to "revoked".
	// Setting to "revoked" is better if we want to keep track of revoked tokens before they expire.
	// But deleting it also works as IsTokenRevoked returns true if not found.
	// For "revoke anytime", deleting is simplest.
	return s.client.Del(ctx, s.authPrefix+token).Err()
}

func (s *TunnelRedisStore) SetActiveDomain(ctx context.Context, domain, sessionID string) error {
	// SET active_domain:<domain> <sessionID> NX EX 24h
	// Set the key only if it doesn't exist to guarantee atomic locking.
	key := "active_domain:" + domain
	// Expiration is a safety net in case of dirty disconnects. The cleanup normally removes this key.
	_, err := s.client.SetArgs(ctx, key, sessionID, redis.SetArgs{
		Mode: "NX",
		TTL:  24 * time.Hour,
	}).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Key already exists, domain is active somewhere else
			return errors.New("domain is currently actively tunneled")
		}
		return fmt.Errorf("failed to set active domain lock: %w", err)
	}
	return nil
}

func (s *TunnelRedisStore) RemoveActiveDomain(ctx context.Context, domain string) error {
	key := "active_domain:" + domain
	return s.client.Del(ctx, key).Err()
}
