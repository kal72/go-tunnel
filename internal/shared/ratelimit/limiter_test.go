package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLimiter_Allow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		rate         int
		burst        int
		requestCount int
		expectAllowed int
	}{
		{
			name:         "burst limit allowed",
			rate:         10,
			burst:        3,
			requestCount: 3,
			expectAllowed: 3,
		},
		{
			name:         "exceed burst rate limited",
			rate:         1,
			burst:        2,
			requestCount: 4,
			expectAllowed: 2,
		},
		{
			name:         "zero rate permits all",
			rate:         0,
			burst:        10,
			requestCount: 5,
			expectAllowed: 5,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			limiter := NewLimiter()
			allowed := 0
			for i := 0; i < tt.requestCount; i++ {
				if limiter.Allow("test-key", tt.rate, tt.burst) {
					allowed++
				}
			}
			assert.Equal(t, tt.expectAllowed, allowed)
		})
	}
}

func TestLimiter_Cleanup(t *testing.T) {
	t.Parallel()

	limiter := NewLimiter()
	limiter.Allow("host-1", 10, 10)
	assert.Len(t, limiter.buckets, 1)

	limiter.Cleanup(time.Hour)
	assert.Len(t, limiter.buckets, 1)

	limiter.Cleanup(0)
	assert.Empty(t, limiter.buckets)
}
