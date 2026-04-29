package state

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type TunnelInfo struct {
	ClientID    string    `json:"client_id"`
	Client      string    `json:"client"`
	Hosts       []string  `json:"hosts"`
	ConnectedAt time.Time `json:"connected_at"`
	LastPing    time.Time `json:"last_ping"`
}

type Store interface {
	Ping(ctx context.Context)
	SetTunnel(ctx context.Context, sessionID string, info TunnelInfo) error
	DeleteTunnel(ctx context.Context, sessionID string) error
	ListTunnels(ctx context.Context) ([]TunnelInfo, error)

	// Token management
	SetToken(ctx context.Context, token string, expiration time.Duration) error
	IsTokenRevoked(ctx context.Context, token string) (bool, error)
	RevokeToken(ctx context.Context, token string) error

	AddDomain(ctx context.Context, domain string) error
	RemoveDomain(ctx context.Context, domain string) error
	ListDomains(ctx context.Context) ([]string, error)
	IsDomainAllowed(ctx context.Context, domain string) (bool, error)
}

type RedisStore struct {
	client     *redis.Client
	prefix     string
	authPrefix string
	domainKey  string
}

func NewRedisStore(addr, pass string, db int) *RedisStore {
	return &RedisStore{
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

func (s *RedisStore) Ping(ctx context.Context) {
	pong, err := s.client.Ping(ctx).Result()
	if err != nil {
		fmt.Println("Redis connection failed:", err)
		return
	}

	fmt.Println("Redis connected:", pong)
}

func (s *RedisStore) SetTunnel(ctx context.Context, sessionID string, info TunnelInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	// Expire after 1 hour if not refreshed
	return s.client.Set(ctx, s.prefix+sessionID, data, 1*time.Hour).Err()
}

func (s *RedisStore) DeleteTunnel(ctx context.Context, sessionID string) error {
	return s.client.Del(ctx, s.prefix+sessionID).Err()
}

func (s *RedisStore) ListTunnels(ctx context.Context) ([]TunnelInfo, error) {
	keys, err := s.client.Keys(ctx, s.prefix+"*").Result()
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return []TunnelInfo{}, nil
	}

	var infos []TunnelInfo
	for _, key := range keys {
		data, err := s.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		var info TunnelInfo
		if err := json.Unmarshal([]byte(data), &info); err == nil {
			infos = append(infos, info)
		}
	}
	return infos, nil
}

func (s *RedisStore) SetToken(ctx context.Context, token string, expiration time.Duration) error {
	return s.client.Set(ctx, s.authPrefix+token, "valid", expiration).Err()
}

func (s *RedisStore) IsTokenRevoked(ctx context.Context, token string) (bool, error) {
	val, err := s.client.Get(ctx, s.authPrefix+token).Result()
	if err == redis.Nil {
		return true, nil // If not in redis, consider it revoked or expired
	}
	if err != nil {
		return false, err
	}
	return val == "revoked", nil
}

func (s *RedisStore) RevokeToken(ctx context.Context, token string) error {
	// We could either delete it or set it to "revoked".
	// Setting to "revoked" is better if we want to keep track of revoked tokens before they expire.
	// But deleting it also works as IsTokenRevoked returns true if not found.
	// For "revoke anytime", deleting is simplest.
	return s.client.Del(ctx, s.authPrefix+token).Err()
}

func (s *RedisStore) AddDomain(ctx context.Context, domain string) error {
	return s.client.SAdd(ctx, s.domainKey, domain).Err()
}

func (s *RedisStore) RemoveDomain(ctx context.Context, domain string) error {
	return s.client.SRem(ctx, s.domainKey, domain).Err()
}

func (s *RedisStore) ListDomains(ctx context.Context) ([]string, error) {
	return s.client.SMembers(ctx, s.domainKey).Result()
}
func (s *RedisStore) IsDomainAllowed(ctx context.Context, domain string) (bool, error) {
	return s.client.SIsMember(ctx, s.domainKey, domain).Result()
}
