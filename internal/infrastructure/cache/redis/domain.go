package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type DomainRedisStore struct {
	client    *redis.Client
	domainKey string
}

func NewDomainRedisStore(addr, pass string, db int) *DomainRedisStore {
	return &DomainRedisStore{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: pass,
			DB:       db,
		}),
		domainKey: "allowed_domains",
	}
}

func (s *DomainRedisStore) Ping(ctx context.Context) {
	pong, err := s.client.Ping(ctx).Result()
	if err != nil {
		fmt.Println("Redis domain store connection failed:", err)
		return
	}
	fmt.Println("Redis domain store connected:", pong)
}

func (s *DomainRedisStore) AddDomain(ctx context.Context, domain string) error {
	return s.client.SAdd(ctx, s.domainKey, domain).Err()
}

func (s *DomainRedisStore) RemoveDomain(ctx context.Context, domain string) error {
	return s.client.SRem(ctx, s.domainKey, domain).Err()
}

func (s *DomainRedisStore) ListDomains(ctx context.Context) ([]string, error) {
	return s.client.SMembers(ctx, s.domainKey).Result()
}

func (s *DomainRedisStore) IsDomainAllowed(ctx context.Context, domain string) (bool, error) {
	return s.client.SIsMember(ctx, s.domainKey, domain).Result()
}
