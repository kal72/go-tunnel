package apikey

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAPIKey_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		want      bool
	}{
		{
			name:      "nil ExpiresAt returns false",
			expiresAt: nil,
			want:      false,
		},
		{
			name:      "future ExpiresAt returns false",
			expiresAt: timePtr(time.Now().Add(24 * time.Hour)),
			want:      false,
		},
		{
			name:      "past ExpiresAt returns true",
			expiresAt: timePtr(time.Now().Add(-24 * time.Hour)),
			want:      true,
		},
		{
			name:      "far future ExpiresAt returns false",
			expiresAt: timePtr(time.Now().Add(365 * 24 * time.Hour)),
			want:      false,
		},
		{
			name:      "one second ago returns true",
			expiresAt: timePtr(time.Now().Add(-1 * time.Second)),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				Name:      "test-key",
				Status:    StatusActive,
				ExpiresAt: tt.expiresAt,
			}
			assert.Equal(t, tt.want, key.IsExpired())
		})
	}
}

func TestAPIKey_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		status    APIKeyStatus
		expiresAt *time.Time
		want      bool
	}{
		{
			name:      "active key with nil expiration is valid",
			status:    StatusActive,
			expiresAt: nil,
			want:      true,
		},
		{
			name:      "active key with future expiration is valid",
			status:    StatusActive,
			expiresAt: timePtr(time.Now().Add(24 * time.Hour)),
			want:      true,
		},
		{
			name:      "active key with past expiration is not valid",
			status:    StatusActive,
			expiresAt: timePtr(time.Now().Add(-24 * time.Hour)),
			want:      false,
		},
		{
			name:      "revoked key with nil expiration is not valid",
			status:    StatusRevoked,
			expiresAt: nil,
			want:      false,
		},
		{
			name:      "revoked key with future expiration is not valid",
			status:    StatusRevoked,
			expiresAt: timePtr(time.Now().Add(24 * time.Hour)),
			want:      false,
		},
		{
			name:      "revoked key with past expiration is not valid",
			status:    StatusRevoked,
			expiresAt: timePtr(time.Now().Add(-24 * time.Hour)),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				Name:      "test-key",
				Status:    tt.status,
				ExpiresAt: tt.expiresAt,
			}
			assert.Equal(t, tt.want, key.IsValid())
		})
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}
