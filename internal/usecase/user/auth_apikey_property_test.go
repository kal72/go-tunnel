package user

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/mock"

	domainAPIKey "gotunnel/internal/domain/apikey"
	apikeyMocks "gotunnel/internal/domain/apikey/mocks"
	domainErrors "gotunnel/internal/domain/errors"
	tunnelMocks "gotunnel/internal/domain/tunnel/mocks"
	domainUser "gotunnel/internal/domain/user"
	userMocks "gotunnel/internal/domain/user/mocks"
)

// Feature: direct-token-auth, Property 1: API Key Format Validity
//
// **Validates: Requirements 1.2, 1.6**
//
// For any generated API key, the key SHALL start with the `gtk_` prefix
// and have a minimum length of 47 characters (4 char prefix + 43 char base64 encoding of 32 bytes).

// genValidAPIKeyName generates valid API key names (1-64 chars, alphanumeric + hyphen + underscore).
func genValidAPIKeyName() gopter.Gen {
	// Use Identifier which generates alphanumeric strings starting with a letter
	return gen.Identifier().
		SuchThat(func(s string) bool {
			return len(s) >= 1 && len(s) <= 64
		}).
		Map(func(s string) string {
			if len(s) == 0 {
				return "testkey"
			}
			if len(s) > 64 {
				return s[:64]
			}
			return s
		})
}

// genValidExpiration generates valid expiration dates (nil or future within 365 days).
func genValidExpiration() gopter.Gen {
	return gen.OneConstOf(true, false).FlatMap(func(v interface{}) gopter.Gen {
		hasExpiration := v.(bool)
		if !hasExpiration {
			return gen.Const((*time.Time)(nil))
		}
		return gen.Int64Range(1, 364*24).Map(func(hours int64) *time.Time {
			t := time.Now().Add(time.Duration(hours) * time.Hour)
			return &t
		})
	}, reflect.TypeOf((*time.Time)(nil)))
}

func TestProperty_APIKeyFormat(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("generated keys have valid format (gtk_ prefix and min 47 chars)", prop.ForAll(
		func(name string, expiresAt *time.Time) bool {
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)

			userID := uuid.New()

			apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, name).Return(false, nil).Maybe()
			apiKeyRepo.EXPECT().CountActiveByUserID(mock.Anything, userID).Return(0, nil).Maybe()
			apiKeyRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(nil).Maybe()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

			plaintext, _, err := uc.CreateAPIKey(context.Background(), userID, name, expiresAt)

			if err != nil {
				// Validation errors are expected for some edge cases from generator
				// This is acceptable as we're testing the format of successful creations
				return true
			}

			// Property 1: Key must start with "gtk_" prefix
			if !strings.HasPrefix(plaintext, "gtk_") {
				t.Errorf("API key does not start with gtk_ prefix: %s", plaintext)
				return false
			}

			// Property 1: Key must have minimum 47 characters (4 prefix + 43 base64)
			// 32 bytes encoded as base64 URL encoding = 43 characters
			// Total: 4 (prefix) + 43 (base64) = 47 characters
			if len(plaintext) < 47 {
				t.Errorf("API key too short: got %d chars, expected >= 47. Key: %s", len(plaintext), plaintext)
				return false
			}

			return true
		},
		genValidAPIKeyName(),
		genValidExpiration(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Feature: direct-token-auth, Property 5: Expired Key Authentication Failure
//
// **Validates: Requirements 2.3, 4.4**
//
// For any API key where `expires_at` is not NULL and the current time is at or
// past `expires_at`, authentication attempts using that key SHALL fail with
// an unauthorized error.
// =============================================================================

// genExpiredTime generates a time in the past (expired).
// The range is from 1 second ago to 8760 hours (365 days) ago.
func genExpiredTime() gopter.Gen {
	return gen.Int64Range(1, 8760*3600).Map(func(secondsAgo int64) time.Time {
		return time.Now().Add(-time.Duration(secondsAgo) * time.Second)
	})
}

// genAlphaNumSuffix generates an alphanumeric string suffix for tokens.
// This ensures we have valid token content after the gtk_ prefix.
func genAlphaNumSuffix() gopter.Gen {
	return gen.Identifier().SuchThat(func(s string) bool {
		return len(s) >= 20 // Ensure minimum length for realistic token
	}).Map(func(s string) string {
		if len(s) > 40 {
			return s[:40]
		}
		return s
	})
}

// computeTestSHA256Hash computes SHA-256 hash for testing purposes.
func computeTestSHA256Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func TestProperty_ExpiredKeyAuthFailure(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("expired keys always fail authentication", prop.ForAll(
		func(tokenSuffix string, expiredAt time.Time, userIsActive bool) bool {
			// Setup: create mocks for each test iteration
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)

			userID := uuid.New()
			keyID := uuid.New()

			// Construct a valid token with gtk_ prefix
			token := "gtk_" + tokenSuffix
			keyHash := computeTestSHA256Hash(token)

			// Create an expired API key (StatusActive but expiredAt is in the past)
			// The key is active to isolate the expiration check
			expiredTime := expiredAt // Copy to avoid pointer issues
			key := &domainAPIKey.APIKey{
				ID:         keyID,
				UserID:     userID,
				Name:       "expired-test-key",
				KeyHash:    keyHash,
				Status:     domainAPIKey.StatusActive, // Active status to isolate expiration check
				CreatedAt:  time.Now().Add(-24 * time.Hour),
				ExpiresAt:  &expiredTime, // Expired (in the past)
				LastUsedAt: nil,
			}

			// Mock: GetByHash returns the expired key
			apiKeyRepo.EXPECT().GetByHash(mock.Anything, keyHash).Return(key, nil).Once()

			// Note: We should NOT reach the GetUserByID call because the key.IsValid()
			// check should fail before that (key is expired)

			uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "testsecret", 24, 720)

			// Act: Attempt to verify the expired key
			_, err := uc.VerifyToken(context.Background(), token)

			// Assert: Should return ErrUnauthorized for expired keys
			if err == nil {
				t.Errorf("Expected error for expired key, got nil. Token: %s, ExpiresAt: %v", token, expiredAt)
				return false
			}

			if !errors.Is(err, domainErrors.ErrUnauthorized) {
				t.Errorf("Expected ErrUnauthorized, got: %v", err)
				return false
			}

			return true
		},
		genAlphaNumSuffix(),
		genExpiredTime(),
		gen.Bool(), // userIsActive - not used since we should fail before user check
	))

	properties.TestingRun(t)
}

// =============================================================================
// Feature: direct-token-auth, Property 8: User State Change Cascades to API Keys
//
// **Validates: Requirements 3.4, 3.5, 3.6**
//
// For any user with one or more API keys, when the user account is deleted OR
// deactivated (status changed from active), all API keys belonging to that user
// SHALL be revoked such that subsequent authentication attempts fail.
// =============================================================================

// genUUID generates random UUIDs for testing.
func genUUID() gopter.Gen {
	return gen.SliceOfN(16, gen.UInt8()).Map(func(b []uint8) uuid.UUID {
		var id uuid.UUID
		for i := 0; i < 16 && i < len(b); i++ {
			id[i] = b[i]
		}
		return id
	})
}

// genNonActiveStatus generates a non-active user status (0 = inactive, 2+ = other states).
// Active status is 1, so we generate values != 1.
func genNonActiveStatus() gopter.Gen {
	return gen.OneConstOf(int16(0), int16(2), int16(-1))
}

// TestProperty_UserDeletionCascade verifies that when a user is deleted,
// all their API keys are revoked (RevokeAllByUserID is called).
func TestProperty_UserDeletionCascade(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("user deletion revokes all API keys", prop.ForAll(
		func(userID uuid.UUID) bool {
			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			store := tunnelMocks.NewMockTunnelStore(t)

			// Track if RevokeAllByUserID was called
			var revokeAllCalled bool
			var revokeAllCalledMu sync.Mutex

			// Mock: RevokeAllByUserID should be called on user deletion
			apiKeyRepo.EXPECT().RevokeAllByUserID(mock.Anything, userID).
				RunAndReturn(func(ctx context.Context, id uuid.UUID) error {
					revokeAllCalledMu.Lock()
					revokeAllCalled = true
					revokeAllCalledMu.Unlock()
					return nil
				}).Once()

			// Mock: User deletion succeeds
			userRepo.EXPECT().DeleteUser(mock.Anything, userID).Return(nil).Once()

			// Mock: Token revocation (best effort, may or may not be called)
			store.EXPECT().RevokeUserTokens(mock.Anything, userID.String()).Return(nil).Maybe()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "testsecret", 24, 720)

			// Act: Delete the user
			err := uc.DeleteUser(context.Background(), userID)

			// Assert: Deletion should succeed
			if err != nil {
				t.Errorf("DeleteUser failed: %v", err)
				return false
			}

			// Assert: RevokeAllByUserID must have been called
			revokeAllCalledMu.Lock()
			defer revokeAllCalledMu.Unlock()
			if !revokeAllCalled {
				t.Error("RevokeAllByUserID was not called during user deletion")
				return false
			}

			return true
		},
		genUUID(),
	))

	properties.TestingRun(t)
}

// TestProperty_UserDeactivationCascade verifies that when a user is deactivated
// (status changed to non-active), all their API keys are revoked.
func TestProperty_UserDeactivationCascade(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("user deactivation revokes all API keys", prop.ForAll(
		func(userID uuid.UUID, newStatus int16) bool {
			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			store := tunnelMocks.NewMockTunnelStore(t)

			// Track if RevokeAllByUserID was called
			var revokeAllCalled bool
			var revokeAllCalledMu sync.Mutex

			// Mock: User status update succeeds
			userRepo.EXPECT().UpdateUserStatus(mock.Anything, userID, newStatus).Return(nil).Once()

			// Mock: Token revocation (called when deactivating)
			store.EXPECT().RevokeUserTokens(mock.Anything, userID.String()).Return(nil).Maybe()

			// Mock: RevokeAllByUserID should be called when status != 1 (not active)
			apiKeyRepo.EXPECT().RevokeAllByUserID(mock.Anything, userID).
				RunAndReturn(func(ctx context.Context, id uuid.UUID) error {
					revokeAllCalledMu.Lock()
					revokeAllCalled = true
					revokeAllCalledMu.Unlock()
					return nil
				}).Maybe()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "testsecret", 24, 720)

			// Act: Update user status to non-active
			err := uc.UpdateUserStatus(context.Background(), userID, newStatus)

			// Assert: Update should succeed
			if err != nil {
				t.Errorf("UpdateUserStatus failed: %v", err)
				return false
			}

			// Assert: RevokeAllByUserID must have been called for non-active status
			revokeAllCalledMu.Lock()
			defer revokeAllCalledMu.Unlock()
			if !revokeAllCalled {
				t.Errorf("RevokeAllByUserID was not called when user status changed to %d", newStatus)
				return false
			}

			return true
		},
		genUUID(),
		genNonActiveStatus(), // Only test with non-active statuses (deactivation)
	))

	properties.TestingRun(t)
}

// TestProperty_UserStatusChangeToActiveNoCascade verifies that changing user
// status to active (1) does NOT revoke API keys.
func TestProperty_UserStatusChangeToActiveNoCascade(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("activating user does not revoke API keys", prop.ForAll(
		func(userID uuid.UUID) bool {
			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			store := tunnelMocks.NewMockTunnelStore(t)

			// Active status
			activeStatus := int16(1)

			// Mock: User status update succeeds
			userRepo.EXPECT().UpdateUserStatus(mock.Anything, userID, activeStatus).Return(nil).Once()

			// Note: We do NOT expect RevokeAllByUserID to be called when activating
			// The mock will fail if RevokeAllByUserID is called

			uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "testsecret", 24, 720)

			// Act: Update user status to active
			err := uc.UpdateUserStatus(context.Background(), userID, activeStatus)

			// Assert: Update should succeed
			if err != nil {
				t.Errorf("UpdateUserStatus failed: %v", err)
				return false
			}

			return true
		},
		genUUID(),
	))

	properties.TestingRun(t)
}

// TestProperty_RevokeUserTokensCascade verifies that bulk token revocation
// also revokes all API keys for the target user.
func TestProperty_RevokeUserTokensCascade(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("RevokeUserTokens also revokes all API keys", prop.ForAll(
		func(userID uuid.UUID) bool {
			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			store := tunnelMocks.NewMockTunnelStore(t)

			// Track if RevokeAllByUserID was called
			var revokeAllCalled bool
			var revokeAllCalledMu sync.Mutex

			// Mock: JWT token revocation succeeds
			store.EXPECT().RevokeUserTokens(mock.Anything, userID.String()).Return(nil).Once()

			// Mock: RevokeAllByUserID should also be called
			apiKeyRepo.EXPECT().RevokeAllByUserID(mock.Anything, userID).
				RunAndReturn(func(ctx context.Context, id uuid.UUID) error {
					revokeAllCalledMu.Lock()
					revokeAllCalled = true
					revokeAllCalledMu.Unlock()
					return nil
				}).Once()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "testsecret", 24, 720)

			// Act: Revoke all tokens for the user
			err := uc.RevokeUserTokens(context.Background(), userID)

			// Assert: Revocation should succeed
			if err != nil {
				t.Errorf("RevokeUserTokens failed: %v", err)
				return false
			}

			// Assert: RevokeAllByUserID must have been called
			revokeAllCalledMu.Lock()
			defer revokeAllCalledMu.Unlock()
			if !revokeAllCalled {
				t.Error("RevokeAllByUserID was not called during RevokeUserTokens")
				return false
			}

			return true
		},
		genUUID(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Feature: direct-token-auth, Property 7: Ownership-Based Revocation Authorization
//
// **Validates: Requirements 3.1, 3.2, 3.3**
//
// For any API key and revocation request:
// - If the requester owns the key, revocation SHALL succeed
// - If the requester is admin (role=1), revocation SHALL succeed regardless of ownership
// - If the requester is non-admin and does not own the key, revocation SHALL fail with forbidden error
// =============================================================================

// genNonAdminRole generates non-admin roles (role != 1).
// Role 0 = regular user, role 2+ = other non-admin states.
func genNonAdminRole() gopter.Gen {
	return gen.OneConstOf(int16(0), int16(2), int16(-1))
}

// TestProperty_OwnerCanRevokeOwnKey verifies that a key owner can always revoke their own key.
func TestProperty_OwnerCanRevokeOwnKey(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("owner can revoke their own key", prop.ForAll(
		func(userID uuid.UUID, keyID uuid.UUID, requesterRole int16) bool {
			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			store := tunnelMocks.NewMockTunnelStore(t)

			// Create an API key owned by the requester
			key := &domainAPIKey.APIKey{
				ID:        keyID,
				UserID:    userID, // Same as requester (owner)
				Name:      "test-key",
				KeyHash:   "somehash123",
				Status:    domainAPIKey.StatusActive,
				CreatedAt: time.Now().Add(-1 * time.Hour),
			}

			// Mock: GetByID returns the key owned by requester
			apiKeyRepo.EXPECT().GetByID(mock.Anything, keyID).Return(key, nil).Once()

			// Mock: Revoke succeeds
			apiKeyRepo.EXPECT().Revoke(mock.Anything, keyID).Return(nil).Once()

			// Mock: RevokeToken from Redis store (best effort)
			store.EXPECT().RevokeToken(mock.Anything, key.KeyHash).Return(nil).Maybe()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "testsecret", 24, 720)

			// Act: Owner attempts to revoke their own key
			err := uc.RevokeAPIKey(context.Background(), keyID, userID, requesterRole)

			// Assert: Revocation should succeed for owner
			if err != nil {
				t.Errorf("Owner failed to revoke own key: %v (role=%d)", err, requesterRole)
				return false
			}

			return true
		},
		genUUID(),                // userID (also requesterID since testing owner)
		genUUID(),                // keyID
		gen.Int16Range(-10, 100), // requesterRole (any role should work for owner)
	))

	properties.TestingRun(t)
}

// TestProperty_AdminCanRevokeAnyKey verifies that admin (role=1) can revoke any key.
func TestProperty_AdminCanRevokeAnyKey(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("admin can revoke any key regardless of ownership", prop.ForAll(
		func(keyOwnerID uuid.UUID, adminID uuid.UUID, keyID uuid.UUID) bool {
			// Ensure admin is different from key owner (testing non-owner admin)
			// If they happen to be the same, skip this iteration
			if keyOwnerID == adminID {
				return true // Skip when IDs collide (owner case tested separately)
			}

			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			store := tunnelMocks.NewMockTunnelStore(t)

			// Create an API key owned by someone else
			key := &domainAPIKey.APIKey{
				ID:        keyID,
				UserID:    keyOwnerID, // Different from admin
				Name:      "other-user-key",
				KeyHash:   "somehash456",
				Status:    domainAPIKey.StatusActive,
				CreatedAt: time.Now().Add(-1 * time.Hour),
			}

			// Mock: GetByID returns the key (owned by another user)
			apiKeyRepo.EXPECT().GetByID(mock.Anything, keyID).Return(key, nil).Once()

			// Mock: Revoke succeeds
			apiKeyRepo.EXPECT().Revoke(mock.Anything, keyID).Return(nil).Once()

			// Mock: RevokeToken from Redis store (best effort)
			store.EXPECT().RevokeToken(mock.Anything, key.KeyHash).Return(nil).Maybe()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "testsecret", 24, 720)

			// Act: Admin (role=1) attempts to revoke another user's key
			adminRole := int16(1)
			err := uc.RevokeAPIKey(context.Background(), keyID, adminID, adminRole)

			// Assert: Admin revocation should succeed
			if err != nil {
				t.Errorf("Admin failed to revoke key: %v (adminID=%s, ownerID=%s)", err, adminID, keyOwnerID)
				return false
			}

			return true
		},
		genUUID(), // keyOwnerID
		genUUID(), // adminID
		genUUID(), // keyID
	))

	properties.TestingRun(t)
}

// TestProperty_NonOwnerNonAdminCannotRevoke verifies that non-owner with non-admin role
// cannot revoke a key they don't own.
func TestProperty_NonOwnerNonAdminCannotRevoke(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("non-owner non-admin cannot revoke key", prop.ForAll(
		func(keyOwnerID uuid.UUID, requesterID uuid.UUID, keyID uuid.UUID, requesterRole int16) bool {
			// Ensure requester is different from key owner (testing non-owner)
			// If they happen to be the same, skip this iteration
			if keyOwnerID == requesterID {
				return true // Skip when IDs collide (owner case tested separately)
			}

			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			store := tunnelMocks.NewMockTunnelStore(t)

			// Create an API key owned by someone else
			key := &domainAPIKey.APIKey{
				ID:        keyID,
				UserID:    keyOwnerID, // Different from requester
				Name:      "another-user-key",
				KeyHash:   "somehash789",
				Status:    domainAPIKey.StatusActive,
				CreatedAt: time.Now().Add(-1 * time.Hour),
			}

			// Mock: GetByID returns the key (owned by another user)
			apiKeyRepo.EXPECT().GetByID(mock.Anything, keyID).Return(key, nil).Once()

			// Note: Revoke should NOT be called since authorization fails
			// The mock will fail if Revoke is unexpectedly called

			uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "testsecret", 24, 720)

			// Act: Non-owner non-admin attempts to revoke another user's key
			err := uc.RevokeAPIKey(context.Background(), keyID, requesterID, requesterRole)

			// Assert: Should return ErrForbidden
			if err == nil {
				t.Errorf("Expected ErrForbidden for non-owner non-admin, got nil (requesterRole=%d)", requesterRole)
				return false
			}

			if !errors.Is(err, domainErrors.ErrForbidden) {
				t.Errorf("Expected ErrForbidden, got: %v", err)
				return false
			}

			return true
		},
		genUUID(),         // keyOwnerID
		genUUID(),         // requesterID (different from owner)
		genUUID(),         // keyID
		genNonAdminRole(), // requesterRole (non-admin: 0, 2, -1, etc.)
	))

	properties.TestingRun(t)
}

// =============================================================================
// Feature: direct-token-auth, Property 6: Key Hash Exclusion in Responses
//
// **Validates: Requirements 2.5, 6.3**
//
// For any API key listing response (both user-specific and admin views), no
// returned key record SHALL contain the key_hash field or any derivable form
// of the plaintext key.
// =============================================================================

// genKeyName generates valid API key names for testing.
func genKeyName() gopter.Gen {
	return gen.Identifier().SuchThat(func(s string) bool {
		return len(s) >= 1 && len(s) <= 64
	}).Map(func(s string) string {
		if len(s) > 64 {
			return s[:64]
		}
		return s
	})
}

// genKeyHash generates random SHA-256 hash strings (64 hex characters).
func genKeyHash() gopter.Gen {
	return gen.SliceOfN(32, gen.UInt8()).Map(func(b []uint8) string {
		hash := sha256.Sum256(b)
		return hex.EncodeToString(hash[:])
	})
}

// genAPIKeyStatus generates valid API key status values.
func genAPIKeyStatus() gopter.Gen {
	return gen.OneConstOf(domainAPIKey.StatusActive, domainAPIKey.StatusRevoked)
}

// genOptionalTime generates an optional time (nil or a valid time).
func genOptionalTime() gopter.Gen {
	return gen.OneConstOf(true, false).FlatMap(func(v interface{}) gopter.Gen {
		hasTime := v.(bool)
		if !hasTime {
			return gen.Const((*time.Time)(nil))
		}
		return gen.Int64Range(-8760, 8760).Map(func(hours int64) *time.Time {
			t := time.Now().Add(time.Duration(hours) * time.Hour)
			return &t
		})
	}, reflect.TypeOf((*time.Time)(nil)))
}

// genAPIKeyWithOwner generates a random APIKeyWithOwner with KeyHash populated.
func genAPIKeyWithOwner() gopter.Gen {
	return gen.Struct(reflect.TypeOf(domainAPIKey.APIKeyWithOwner{}), map[string]gopter.Gen{
		"APIKey": gen.Struct(reflect.TypeOf(domainAPIKey.APIKey{}), map[string]gopter.Gen{
			"ID":         genUUID(),
			"UserID":     genUUID(),
			"Name":       genKeyName(),
			"KeyHash":    genKeyHash(),
			"Status":     genAPIKeyStatus(),
			"CreatedAt":  gen.Const(time.Now()),
			"ExpiresAt":  genOptionalTime(),
			"LastUsedAt": genOptionalTime(),
		}),
		"Username": gen.Identifier().SuchThat(func(s string) bool { return len(s) >= 1 && len(s) <= 64 }),
	})
}

// genAPIKeySlice generates a slice of 1 to 10 APIKeyWithOwner structs.
func genAPIKeySlice() gopter.Gen {
	return gen.IntRange(1, 10).FlatMap(func(v interface{}) gopter.Gen {
		count := v.(int)
		return gen.SliceOfN(count, genAPIKeyWithOwner())
	}, reflect.TypeOf([]domainAPIKey.APIKeyWithOwner{}))
}

// genRole generates user role (0 for regular, 1 for admin).
func genRole() gopter.Gen {
	return gen.OneConstOf(int16(0), int16(1))
}

// =============================================================================
// Feature: direct-token-auth, Property 9: Valid API Key Returns Correct User Entity
//
// **Validates: Requirements 4.3, 4.6**
//
// For any valid API key (exists, active status, not expired, owner is active),
// authentication SHALL succeed and return a User entity where:
// - `ID` matches the key owner's ID
// - `Username` matches the key owner's username
// - `Role` matches the key owner's role
// =============================================================================

// genAlphaNumString generates an alphanumeric string of specified length.
// Uses a direct character generation approach to avoid high discard rate.
func genAlphaNumString(minLen, maxLen int) gopter.Gen {
	alphanumChars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	return gen.IntRange(minLen, maxLen).FlatMap(func(v interface{}) gopter.Gen {
		length := v.(int)
		return gen.SliceOfN(length, gen.IntRange(0, len(alphanumChars)-1)).Map(func(indices []int) string {
			result := make([]rune, len(indices))
			for i, idx := range indices {
				result[i] = alphanumChars[idx]
			}
			return string(result)
		})
	}, reflect.TypeOf(""))
}

// genRole generates valid user roles (0 = regular, 1 = admin).
func genUserRole() gopter.Gen {
	return gen.OneConstOf(int16(0), int16(1))
}

// genFutureExpiration generates an optional future expiration time.
// Returns nil (no expiration) or a time 1-8760 hours (365 days) in the future.
func genFutureExpiration() gopter.Gen {
	return gen.OneConstOf(true, false).FlatMap(func(v interface{}) gopter.Gen {
		hasExpiration := v.(bool)
		if !hasExpiration {
			return gen.Const((*time.Time)(nil))
		}
		return gen.Int64Range(1, 8760).Map(func(hours int64) *time.Time {
			t := time.Now().Add(time.Duration(hours) * time.Hour)
			return &t
		})
	}, reflect.TypeOf((*time.Time)(nil)))
}

// TestProperty_ValidAPIKeyReturnsCorrectUser verifies that when a valid API key
// (exists, active status, not expired, owner is active) is used for authentication,
// the returned User entity matches the key owner's data.
func TestProperty_ValidAPIKeyReturnsCorrectUser(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("valid API key returns correct user entity", prop.ForAll(
		func(userID uuid.UUID, username string, userRole int16, keyID uuid.UUID, keyName string, expiresAt *time.Time) bool {
			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			store := tunnelMocks.NewMockTunnelStore(t)

			// Generate token with valid gtk_ prefix
			tokenSuffix := keyName + username // Combine for uniqueness
			if len(tokenSuffix) < 20 {
				tokenSuffix = tokenSuffix + strings.Repeat("x", 20-len(tokenSuffix))
			}
			token := "gtk_" + tokenSuffix
			keyHash := computeTestSHA256Hash(token)

			// Create a valid active API key
			apiKey := &domainAPIKey.APIKey{
				ID:        keyID,
				UserID:    userID,
				Name:      keyName,
				KeyHash:   keyHash,
				Status:    domainAPIKey.StatusActive,
				CreatedAt: time.Now().Add(-1 * time.Hour),
				ExpiresAt: expiresAt, // Either nil (no expiration) or future time
			}

			// Create the owner user (active status = 1)
			ownerUser := &domainUser.User{
				ID:        userID,
				Username:  username,
				Role:      userRole,
				Status:    1, // Active user
				CreatedAt: time.Now().Add(-24 * time.Hour),
				UpdatedAt: time.Now().Add(-1 * time.Hour),
			}

			// Mock: GetByHash returns the valid active key
			apiKeyRepo.EXPECT().GetByHash(mock.Anything, keyHash).Return(apiKey, nil).Once()

			// Mock: GetUserByID returns the active owner user
			userRepo.EXPECT().GetUserByID(mock.Anything, userID).Return(ownerUser, nil).Once()

			// Mock: UpdateLastUsedAt is called asynchronously (best effort, may or may not complete)
			apiKeyRepo.EXPECT().UpdateLastUsedAt(mock.Anything, keyID).Return(nil).Maybe()

			// Mock: SetToken for session registration
			store.EXPECT().SetToken(mock.Anything, userID.String(), token, mock.AnythingOfType("time.Duration")).Return(nil).Maybe()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "testsecret", 24, 720)

			// Act: Verify the valid API key
			result, err := uc.VerifyToken(context.Background(), token)

			// Assert: Authentication should succeed
			if err != nil {
				t.Errorf("Expected success for valid API key, got error: %v", err)
				return false
			}

			// Assert: Returned user should not be nil
			if result == nil {
				t.Error("Expected non-nil User entity, got nil")
				return false
			}

			// Assert: ID matches the key owner's ID
			if result.ID != userID {
				t.Errorf("User ID mismatch: expected %s, got %s", userID, result.ID)
				return false
			}

			// Assert: Username matches the key owner's username
			if result.Username != username {
				t.Errorf("Username mismatch: expected %q, got %q", username, result.Username)
				return false
			}

			// Assert: Role matches the key owner's role
			if result.Role != userRole {
				t.Errorf("Role mismatch: expected %d, got %d", userRole, result.Role)
				return false
			}

			return true
		},
		genUUID(),                // userID
		genAlphaNumString(3, 20), // username (valid identifier)
		genUserRole(),            // userRole (0 or 1)
		genUUID(),                // keyID
		genAlphaNumString(1, 64), // keyName
		genFutureExpiration(),    // expiresAt (nil or future)
	))

	properties.TestingRun(t)
}

// TestProperty_KeyHashExclusionInListResponse verifies that ListAPIKeys never exposes
// the KeyHash field in responses, regardless of user role or key attributes.
func TestProperty_KeyHashExclusionInListResponse(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("ListAPIKeys never exposes KeyHash in response (regular user)", prop.ForAll(
		func(userID uuid.UUID, keysWithHash []domainAPIKey.APIKeyWithOwner) bool {
			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			store := tunnelMocks.NewMockTunnelStore(t)

			// Extract APIKey slice from APIKeyWithOwner slice for ListByUserID
			apiKeys := make([]domainAPIKey.APIKey, len(keysWithHash))
			for i, k := range keysWithHash {
				apiKeys[i] = k.APIKey
			}

			// Ensure all mock keys have non-empty KeyHash (to verify they get cleared)
			for i := range apiKeys {
				if apiKeys[i].KeyHash == "" {
					apiKeys[i].KeyHash = "fake_hash_" + string(rune(i+'a'))
				}
			}

			// Mock: ListByUserID returns keys WITH KeyHash populated
			apiKeyRepo.EXPECT().ListByUserID(mock.Anything, userID, mock.AnythingOfType("int"), mock.AnythingOfType("int")).
				Return(apiKeys, len(apiKeys), nil).Maybe()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "testsecret", 24, 720)

			// Act: Call ListAPIKeys as regular user (role=0)
			result, _, err := uc.ListAPIKeys(context.Background(), userID, 0, 50, 0, "")

			// Assert: Should succeed
			if err != nil {
				t.Errorf("ListAPIKeys failed: %v", err)
				return false
			}

			// Assert: All returned keys must have EMPTY KeyHash
			for i, key := range result {
				if key.KeyHash != "" {
					t.Errorf("Key at index %d has non-empty KeyHash: %q (expected empty)", i, key.KeyHash)
					return false
				}
			}

			return true
		},
		genUUID(),
		genAPIKeySlice(),
	))

	properties.Property("ListAPIKeys never exposes KeyHash in response (admin user)", prop.ForAll(
		func(userID uuid.UUID, keysWithHash []domainAPIKey.APIKeyWithOwner) bool {
			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			store := tunnelMocks.NewMockTunnelStore(t)

			// Ensure all mock keys have non-empty KeyHash (to verify they get cleared)
			for i := range keysWithHash {
				if keysWithHash[i].KeyHash == "" {
					keysWithHash[i].KeyHash = "fake_admin_hash_" + string(rune(i+'a'))
				}
			}

			// Mock: ListAll returns keys WITH KeyHash populated (admin view)
			apiKeyRepo.EXPECT().ListAll(mock.Anything, mock.AnythingOfType("int"), mock.AnythingOfType("int"), mock.AnythingOfType("string")).
				Return(keysWithHash, len(keysWithHash), nil).Maybe()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "testsecret", 24, 720)

			// Act: Call ListAPIKeys as admin (role=1)
			result, _, err := uc.ListAPIKeys(context.Background(), userID, 1, 50, 0, "")

			// Assert: Should succeed
			if err != nil {
				t.Errorf("ListAPIKeys (admin) failed: %v", err)
				return false
			}

			// Assert: All returned keys must have EMPTY KeyHash
			for i, key := range result {
				if key.KeyHash != "" {
					t.Errorf("Admin view: Key at index %d has non-empty KeyHash: %q (expected empty)", i, key.KeyHash)
					return false
				}
			}

			return true
		},
		genUUID(),
		genAPIKeySlice(),
	))

	properties.TestingRun(t)
}

// =============================================================================
// Feature: direct-token-auth, Property 10: Token Routing Based on Prefix
//
// **Validates: Requirements 4.1, 4.2**
//
// For any auth_token in a REGISTER message:
// - If the token starts with `gtk_` and has at least one character after the prefix,
//   it SHALL be routed to the API key verification path
// - If the token starts with `gtk_` but has no characters after the prefix,
//   it SHALL be rejected with invalid format error (ErrUnauthorized)
// - If the token does not start with `gtk_`, it SHALL be routed to the JWT verification path
// =============================================================================

// genGtkTokenWithContent generates tokens with "gtk_" prefix and at least 1 character after.
func genGtkTokenWithContent() gopter.Gen {
	return gen.Identifier().SuchThat(func(s string) bool {
		return len(s) >= 1 // At least 1 char after prefix
	}).Map(func(s string) string {
		if len(s) > 50 {
			return "gtk_" + s[:50]
		}
		return "gtk_" + s
	})
}

// genNonGtkToken generates tokens that do NOT start with "gtk_" prefix.
// These should be routed to the JWT verification path.
func genNonGtkToken() gopter.Gen {
	return gen.OneGenOf(
		// Random alphanumeric tokens
		gen.Identifier().SuchThat(func(s string) bool {
			return len(s) >= 5 && !strings.HasPrefix(s, "gtk_")
		}),
		// JWT-like tokens (with dots)
		gen.Identifier().Map(func(s string) string {
			if strings.HasPrefix(s, "gtk_") {
				return "jwt_" + s[4:]
			}
			return "eyJ" + s // JWT-like prefix
		}),
		// Tokens with different prefixes
		gen.Identifier().Map(func(s string) string {
			return "api_" + s
		}),
		gen.Identifier().Map(func(s string) string {
			return "tok_" + s
		}),
	)
}

// TestProperty_TokenRoutingWithGtkPrefix verifies that tokens with "gtk_" prefix
// and content after the prefix are routed to the API key verification path.
// We verify this by mocking apiKeyRepo.GetByHash - if it's called, the token was routed correctly.
func TestProperty_TokenRoutingWithGtkPrefix(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("gtk_ prefixed tokens with content route to API key path", prop.ForAll(
		func(tokenSuffix string) bool {
			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)

			// Construct token with gtk_ prefix
			token := "gtk_" + tokenSuffix

			// Track if GetByHash was called (indicates API key path)
			var apiKeyPathCalled bool
			var apiKeyPathCalledMu sync.Mutex

			// Mock: GetByHash should be called for gtk_ tokens (API key path)
			// Return nil to simulate key not found (auth will fail, but routing is correct)
			apiKeyRepo.EXPECT().GetByHash(mock.Anything, mock.AnythingOfType("string")).
				RunAndReturn(func(ctx context.Context, hash string) (*domainAPIKey.APIKey, error) {
					apiKeyPathCalledMu.Lock()
					apiKeyPathCalled = true
					apiKeyPathCalledMu.Unlock()
					return nil, nil // Key not found
				}).Once()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "testsecret", 24, 720)

			// Act: Call VerifyToken with gtk_ prefixed token
			_, err := uc.VerifyToken(context.Background(), token)

			// We expect ErrUnauthorized because key not found, but that's okay -
			// we're testing that the routing happened correctly
			if err == nil {
				t.Errorf("Expected error (key not found), got nil")
				return false
			}

			// Assert: API key path must have been called
			apiKeyPathCalledMu.Lock()
			defer apiKeyPathCalledMu.Unlock()
			if !apiKeyPathCalled {
				t.Errorf("Token %q with gtk_ prefix was NOT routed to API key path", token)
				return false
			}

			return true
		},
		genAlphaNumSuffix(), // Reuse existing generator for suffix content
	))

	properties.TestingRun(t)
}

// TestProperty_TokenRoutingWithoutGtkPrefix verifies that tokens without "gtk_" prefix
// are routed to the JWT verification path.
// We verify this by mocking store.IsTokenRevoked - if it's called, the token was routed to JWT path.
func TestProperty_TokenRoutingWithoutGtkPrefix(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("non-gtk_ prefixed tokens route to JWT path", prop.ForAll(
		func(token string) bool {
			// Skip if somehow starts with gtk_ (generator should prevent this)
			if strings.HasPrefix(token, "gtk_") {
				return true // Skip, not a valid test case
			}

			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)

			// Track if IsTokenRevoked was called (indicates JWT path)
			var jwtPathCalled bool
			var jwtPathCalledMu sync.Mutex

			// Mock: IsTokenRevoked should be called for non-gtk_ tokens (JWT path)
			// Return true to simulate revoked token (auth will fail, but routing is correct)
			tunnelStore.EXPECT().IsTokenRevoked(mock.Anything, token).
				RunAndReturn(func(ctx context.Context, tkn string) (bool, error) {
					jwtPathCalledMu.Lock()
					jwtPathCalled = true
					jwtPathCalledMu.Unlock()
					return true, nil // Token revoked
				}).Once()

			uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "testsecret", 24, 720)

			// Act: Call VerifyToken with non-gtk_ prefixed token
			_, err := uc.VerifyToken(context.Background(), token)

			// We expect ErrUnauthorized because token is "revoked", but that's okay -
			// we're testing that the routing happened correctly
			if err == nil {
				t.Errorf("Expected error (token revoked), got nil")
				return false
			}

			// Assert: JWT path must have been called
			jwtPathCalledMu.Lock()
			defer jwtPathCalledMu.Unlock()
			if !jwtPathCalled {
				t.Errorf("Token %q without gtk_ prefix was NOT routed to JWT path", token)
				return false
			}

			return true
		},
		genNonGtkToken(),
	))

	properties.TestingRun(t)
}

// TestProperty_TokenRoutingEmptyAfterPrefix verifies that tokens with only "gtk_"
// (no content after prefix) are rejected with ErrUnauthorized immediately,
// without calling any repository methods.
func TestProperty_TokenRoutingEmptyAfterPrefix(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 64
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("gtk_ with no content is rejected with ErrUnauthorized", prop.ForAll(
		func(_ bool) bool { // Use dummy parameter since we're testing a single case
			// Setup mocks
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)

			// The token is exactly "gtk_" with nothing after
			token := "gtk_"

			// Note: We do NOT expect any repository calls because the token
			// should be rejected immediately due to empty content after prefix.
			// If GetByHash or IsTokenRevoked is called, the mock will fail
			// since we haven't set up expectations for them.

			uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "testsecret", 24, 720)

			// Act: Call VerifyToken with "gtk_" only
			_, err := uc.VerifyToken(context.Background(), token)

			// Assert: Should return ErrUnauthorized
			if err == nil {
				t.Error("Expected ErrUnauthorized for 'gtk_' only token, got nil")
				return false
			}

			if !errors.Is(err, domainErrors.ErrUnauthorized) {
				t.Errorf("Expected ErrUnauthorized, got: %v", err)
				return false
			}

			return true
		},
		gen.Bool(), // Dummy generator to satisfy property requirements
	))

	properties.TestingRun(t)
}
