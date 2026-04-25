package state

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

type TunnelInfo struct {
	Client      string    `json:"client"`
	Hosts       []string  `json:"hosts"`
	ConnectedAt time.Time `json:"connected_at"`
	LastPing    time.Time `json:"last_ping"`
}

type Store interface {
	SetTunnel(ctx context.Context, sessionID string, info TunnelInfo) error
	DeleteTunnel(ctx context.Context, sessionID string) error
	ListTunnels(ctx context.Context) ([]TunnelInfo, error)
}

type RedisStore struct {
	client *redis.Client
	prefix string
}

func NewRedisStore(addr, pass string, db int) *RedisStore {
	return &RedisStore{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: pass,
			DB:       db,
		}),
		prefix: "tunnel:",
	}
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
