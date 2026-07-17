package user

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	domainAPIKey "gotunnel/internal/domain/apikey"
	domainErrors "gotunnel/internal/domain/errors"
	domainTunnel "gotunnel/internal/domain/tunnel"
	domainUser "gotunnel/internal/domain/user"

	util "gotunnel/internal/shared/crypto"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// API Key constants for Direct Token Authentication feature.
const (
	// apiKeyPrefix is the prefix for all generated API keys to distinguish from JWT tokens.
	apiKeyPrefix = "gtk_"
	// apiKeyByteLen is the number of random bytes used for API key generation (256 bits of entropy).
	apiKeyByteLen = 32
	// maxKeysPerUser is the maximum number of active (non-revoked, non-expired) API keys per user.
	maxKeysPerUser = 10
	// maxExpiryDays is the maximum number of days an API key can be valid from creation.
	maxExpiryDays = 365
)

// validateKeyName validates API key name according to constraints.
// Name must be 1-64 characters, alphanumeric with hyphens and underscores only.
func validateKeyName(name string) error {
	if name == "" || len(name) > 64 {
		return errors.New("name is required and must be 1-64 characters")
	}
	// Check for valid characters: [a-zA-Z0-9_-]
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return errors.New("name can only contain alphanumeric characters, hyphens, and underscores")
		}
	}
	return nil
}

type authUsecase struct {
	userRepo          domainUser.UserRepository
	apiKeyRepo        domainAPIKey.APIKeyRepository
	store             domainTunnel.TunnelStore
	jwtSecret         string
	webJWTExpireHours int
	cliJWTExpireHours int
}

func NewAuthUsecase(userRepo domainUser.UserRepository, apiKeyRepo domainAPIKey.APIKeyRepository, store domainTunnel.TunnelStore, jwtSecret string, webExpireHours, cliExpireHours int) AuthUsecase {
	if webExpireHours <= 0 {
		webExpireHours = 24
	}
	if cliExpireHours <= 0 {
		cliExpireHours = 720
	}
	return &authUsecase{
		userRepo:          userRepo,
		apiKeyRepo:        apiKeyRepo,
		store:             store,
		jwtSecret:         jwtSecret,
		webJWTExpireHours: webExpireHours,
		cliJWTExpireHours: cliExpireHours,
	}
}

func (u *authUsecase) GetWebExpireDuration() time.Duration {
	return time.Duration(u.webJWTExpireHours) * time.Hour
}

func (u *authUsecase) authenticateUser(ctx context.Context, username, password string) (*domainUser.User, error) {
	user, err := u.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != 1 {
		return nil, domainErrors.ErrUnauthorized
	}

	if !util.CheckPasswordHash(password, user.Password) {
		return nil, domainErrors.ErrUnauthorized
	}
	return user, nil
}

func (u *authUsecase) issueToken(ctx context.Context, user *domainUser.User, expireHours int) (string, error) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	csrfToken := hex.EncodeToString(b)

	expiration := time.Duration(expireHours) * time.Hour
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.ID.String(),
		"user": user.Username,
		"role": user.Role,
		"csrf": csrfToken,
		"exp":  time.Now().Add(expiration).Unix(),
	})

	tokenString, err := token.SignedString([]byte(u.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	err = u.store.SetToken(ctx, user.ID.String(), tokenString, expiration)
	if err != nil {
		return "", fmt.Errorf("failed to save token session: %w", err)
	}

	return tokenString, nil
}

func (u *authUsecase) Login(ctx context.Context, username, password string) (string, error) {
	user, err := u.authenticateUser(ctx, username, password)
	if err != nil {
		return "", err
	}
	return u.issueToken(ctx, user, u.webJWTExpireHours)
}

func (u *authUsecase) LoginCLI(ctx context.Context, username, password string) (string, error) {
	user, err := u.authenticateUser(ctx, username, password)
	if err != nil {
		return "", err
	}
	return u.issueToken(ctx, user, u.cliJWTExpireHours)
}

// VerifyToken authenticates a user using either an API key or JWT token.
// It routes to verifyAPIKey for tokens starting with "gtk_" prefix,
// otherwise routes to verifyJWT for JWT tokens.
func (u *authUsecase) VerifyToken(ctx context.Context, tokenStr string) (*domainUser.User, error) {
	// Route to API Key verification if prefix matches
	if strings.HasPrefix(tokenStr, apiKeyPrefix) {
		return u.verifyAPIKey(ctx, tokenStr)
	}

	// Existing JWT verification path
	return u.verifyJWT(ctx, tokenStr)
}

// verifyJWT authenticates a user using a JWT token.
// It checks if the token is revoked, parses and validates the JWT,
// extracts user info from claims, and returns the User entity.
func (u *authUsecase) verifyJWT(ctx context.Context, tokenStr string) (*domainUser.User, error) {
	revoked, err := u.store.IsTokenRevoked(ctx, tokenStr)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, domainErrors.ErrUnauthorized
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(u.jwtSecret), nil
	})

	if err != nil || !token.Valid {
		return nil, domainErrors.ErrUnauthorized
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, domainErrors.ErrUnauthorized
	}

	username, ok := claims["user"].(string)
	if !ok {
		return nil, domainErrors.ErrUnauthorized
	}

	user, err := u.userRepo.GetUserByUsername(ctx, username)
	if err != nil || user == nil {
		return nil, domainErrors.ErrUnauthorized
	}

	if csrf, ok := claims["csrf"].(string); ok {
		user.CSRFToken = csrf
	}

	return user, nil
}

func (u *authUsecase) Logout(ctx context.Context, tokenStr string) error {
	return u.store.RevokeToken(ctx, tokenStr)
}

func (u *authUsecase) CreateUser(ctx context.Context, username, password string, role int16) error {
	hash, err := util.HashPassword(password)
	if err != nil {
		return err
	}

	user := &domainUser.User{
		Username: username,
		Password: hash,
		Role:     role,
		Status:   1,
	}

	return u.userRepo.CreateUser(ctx, user)
}

func (u *authUsecase) ListUsers(ctx context.Context) ([]domainUser.User, error) {
	return u.userRepo.GetUsers(ctx)
}

func (u *authUsecase) UpdateUserStatus(ctx context.Context, id uuid.UUID, status int16) error {
	err := u.userRepo.UpdateUserStatus(ctx, id, status)
	if err == nil && status != 1 {
		// User deactivated - revoke all tokens and API keys
		_ = u.store.RevokeUserTokens(ctx, id.String())
		if u.apiKeyRepo != nil {
			_ = u.apiKeyRepo.RevokeAllByUserID(ctx, id)
		}
	}
	return err
}

func (u *authUsecase) UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error {
	hash, err := util.HashPassword(password)
	if err != nil {
		return err
	}
	err = u.userRepo.UpdateUserPassword(ctx, id, hash)
	if err == nil {
		_ = u.store.RevokeUserTokens(ctx, id.String())
	}
	return err
}

func (u *authUsecase) DeleteUser(ctx context.Context, id uuid.UUID) error {
	// Revoke all API keys first (invalidates sessions before cascade delete)
	if u.apiKeyRepo != nil {
		_ = u.apiKeyRepo.RevokeAllByUserID(ctx, id)
	}

	err := u.userRepo.DeleteUser(ctx, id)
	if err == nil {
		_ = u.store.RevokeUserTokens(ctx, id.String())
	}
	return err
}

func (u *authUsecase) RevokeUserTokens(ctx context.Context, targetUserID uuid.UUID) error {
	// Revoke JWT sessions
	err := u.store.RevokeUserTokens(ctx, targetUserID.String())

	// Also revoke all API keys (best effort)
	if u.apiKeyRepo != nil {
		_ = u.apiKeyRepo.RevokeAllByUserID(ctx, targetUserID)
	}

	return err
}

// CreateAPIKey creates a new API key for a user.
// It validates the name, checks for duplicates, enforces the max keys limit,
// validates the expiration date, generates a cryptographically secure key,
// and persists it to the database. Returns the plaintext key (once) and key metadata.
func (u *authUsecase) CreateAPIKey(ctx context.Context, userID uuid.UUID, name string, expiresAt *time.Time) (string, *domainAPIKey.APIKey, error) {
	// 1. Validate name (1-64 chars, alphanumeric + hyphen + underscore)
	if err := validateKeyName(name); err != nil {
		return "", nil, err
	}

	// 2. Check for duplicate name
	exists, err := u.apiKeyRepo.ExistsActiveByName(ctx, userID, name)
	if err != nil {
		return "", nil, fmt.Errorf("check duplicate name: %w", err)
	}
	if exists {
		return "", nil, domainErrors.ErrAlreadyExists
	}

	// 3. Check max keys limit
	count, err := u.apiKeyRepo.CountActiveByUserID(ctx, userID)
	if err != nil {
		return "", nil, fmt.Errorf("count active keys: %w", err)
	}
	if count >= maxKeysPerUser {
		return "", nil, fmt.Errorf("maximum of %d active API keys reached", maxKeysPerUser)
	}

	// 4. Validate expiration date
	if expiresAt != nil {
		if expiresAt.Before(time.Now()) {
			return "", nil, errors.New("expiration date must be in the future")
		}
		if expiresAt.After(time.Now().AddDate(0, 0, maxExpiryDays)) {
			return "", nil, fmt.Errorf("expiration date cannot exceed %d days", maxExpiryDays)
		}
	}

	// 5. Generate cryptographically secure random bytes
	rawBytes := make([]byte, apiKeyByteLen)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", nil, fmt.Errorf("generate random bytes: %w", err)
	}

	// 6. Create plaintext key with prefix
	plaintext := apiKeyPrefix + base64.URLEncoding.EncodeToString(rawBytes)

	// 7. Hash for storage (SHA-256)
	hash := sha256.Sum256([]byte(plaintext))
	keyHash := hex.EncodeToString(hash[:])

	// 8. Create and persist record
	key := &domainAPIKey.APIKey{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      name,
		KeyHash:   keyHash,
		Status:    domainAPIKey.StatusActive,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	if err := u.apiKeyRepo.Create(ctx, key); err != nil {
		return "", nil, fmt.Errorf("persist API key: %w", err)
	}

	return plaintext, key, nil
}

// ListAPIKeys lists API keys for a user or all users (admin).
// For admin (role=1), list all keys with optional username filter.
// For regular users, list only their own keys.
// Returns keys without key_hash field and supports pagination with limit and offset.
func (u *authUsecase) ListAPIKeys(ctx context.Context, userID uuid.UUID, role int16, limit, offset int, usernameFilter string) ([]domainAPIKey.APIKeyWithOwner, int, error) {
	// For admin (role=1), list all keys with optional username filter
	if role == 1 {
		keys, total, err := u.apiKeyRepo.ListAll(ctx, limit, offset, usernameFilter)
		if err != nil {
			return nil, 0, err
		}
		// Clear KeyHash to prevent exposure (Property 6: Key Hash Exclusion)
		for i := range keys {
			keys[i].KeyHash = ""
		}
		return keys, total, nil
	}

	// For regular users, list only their own keys
	keys, total, err := u.apiKeyRepo.ListByUserID(ctx, userID, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	// Convert to APIKeyWithOwner and clear KeyHash (Property 6: Key Hash Exclusion)
	result := make([]domainAPIKey.APIKeyWithOwner, len(keys))
	for i, key := range keys {
		key.KeyHash = "" // Clear before copying
		result[i] = domainAPIKey.APIKeyWithOwner{APIKey: key}
	}
	return result, total, nil
}

// RevokeAPIKey revokes an API key by ID.
// Authorization rules:
// - Owner can revoke their own key
// - Admin (role=1) can revoke any key
// - Non-owner non-admin returns forbidden error
// After revocation, the key's session is deleted from Redis store (best effort).
func (u *authUsecase) RevokeAPIKey(ctx context.Context, keyID, requesterID uuid.UUID, requesterRole int16) error {
	// 1. Get key by ID
	key, err := u.apiKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("get API key: %w", err)
	}
	if key == nil {
		return domainErrors.ErrNotFound
	}

	// 2. Verify ownership or admin role
	isOwner := key.UserID == requesterID
	isAdmin := requesterRole == 1
	if !isOwner && !isAdmin {
		return domainErrors.ErrForbidden
	}

	// 3. Revoke the key in database
	if err := u.apiKeyRepo.Revoke(ctx, keyID); err != nil {
		return fmt.Errorf("revoke API key: %w", err)
	}

	// 4. Delete session from Redis store (best effort, can fail silently)
	// The key hash is used as the token identifier in Redis
	_ = u.store.RevokeToken(ctx, key.KeyHash)

	return nil
}

// DeleteAPIKey permanently deletes an API key by ID from the database.
// Requires ownership or admin role.
func (u *authUsecase) DeleteAPIKey(ctx context.Context, keyID, requesterID uuid.UUID, requesterRole int16) error {
	// 1. Get key by ID
	key, err := u.apiKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("get API key: %w", err)
	}
	if key == nil {
		return domainErrors.ErrNotFound
	}

	// 2. Verify ownership or admin role
	isOwner := key.UserID == requesterID
	isAdmin := requesterRole == 1
	if !isOwner && !isAdmin {
		return domainErrors.ErrForbidden
	}

	// 3. Delete session from Redis store (best effort)
	_ = u.store.RevokeToken(ctx, key.KeyHash)

	// 4. Permanently delete from database
	if err := u.apiKeyRepo.Delete(ctx, keyID); err != nil {
		return fmt.Errorf("delete API key: %w", err)
	}

	return nil
}

// GetAPIKeyByID retrieves an API key by ID.
// Returns ErrNotFound if the key doesn't exist.
func (u *authUsecase) GetAPIKeyByID(ctx context.Context, keyID uuid.UUID) (*domainAPIKey.APIKey, error) {
	key, err := u.apiKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("get API key: %w", err)
	}
	if key == nil {
		return nil, domainErrors.ErrNotFound
	}
	return key, nil
}

// verifyAPIKey authenticates a user using an API key token.
// It validates the token format, looks up the key by hash, checks key validity,
// verifies the owner user is active, and registers the session in Redis.
// All authentication failures return ErrUnauthorized to prevent information leakage.
func (u *authUsecase) verifyAPIKey(ctx context.Context, tokenStr string) (*domainUser.User, error) {
	// 1. Validate format: must have content after prefix
	if len(tokenStr) <= len(apiKeyPrefix) {
		return nil, domainErrors.ErrUnauthorized
	}

	// 2. Compute hash for lookup
	hash := sha256.Sum256([]byte(tokenStr))
	keyHash := hex.EncodeToString(hash[:])

	// 3. Lookup key by hash
	key, err := u.apiKeyRepo.GetByHash(ctx, keyHash)
	if err != nil {
		return nil, domainErrors.ErrUnauthorized
	}
	if key == nil {
		return nil, domainErrors.ErrUnauthorized
	}

	// 4. Check key validity (status + expiration)
	if !key.IsValid() {
		return nil, domainErrors.ErrUnauthorized
	}

	// 5. Lookup owner user
	user, err := u.userRepo.GetUserByID(ctx, key.UserID)
	if err != nil || user == nil {
		return nil, domainErrors.ErrUnauthorized
	}

	// 6. Check user is active
	if user.Status != 1 {
		return nil, domainErrors.ErrUnauthorized
	}

	// 7. Async update last_used_at (non-blocking)
	go func() {
		defer func() { _ = recover() }() // Panic recovery per convention
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = u.apiKeyRepo.UpdateLastUsedAt(ctx, key.ID)
	}()

	return user, nil
}
