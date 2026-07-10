# Implementation Plan: Direct Token Authentication

## Overview

Fitur ini menambahkan mekanisme autentikasi API Key (Direct Token) untuk CLI client go-tunnel. Implementasi mencakup domain layer (entity + repository), infrastructure layer (PostgreSQL), usecase layer (business logic), delivery layer (Web API + HTML template), dan modifikasi CLI client untuk mendukung `--token` flag dan `GOTUNNEL_TOKEN` environment variable.

## Tasks

- [ ] 1. Set up database schema for API keys
  - [ ] 1.1 Create database migration for api_keys table
    - Create `db/migrations/000005_create_api_keys_table.up.sql` with table definition
    - Create `db/migrations/000005_create_api_keys_table.down.sql` for rollback
    - Include indexes for key_hash, user_id, and active keys
    - Add foreign key constraint to users table with ON DELETE CASCADE
    - _Requirements: 2.1, 2.2_

- [ ] 2. Implement domain layer for API keys
  - [ ] 2.1 Create APIKey entity
    - Create `internal/domain/apikey/entity.go` with APIKey struct
    - Define APIKeyStatus type with StatusActive and StatusRevoked constants
    - Implement IsExpired() and IsValid() methods
    - Create APIKeyWithOwner struct for admin listing
    - _Requirements: 2.1, 2.3, 2.4_

  - [ ] 2.2 Create APIKeyRepository interface
    - Create `internal/domain/apikey/repository.go` with repository interface
    - Define Create, GetByHash, GetByID, ListByUserID, ListAll methods
    - Define CountActiveByUserID, ExistsActiveByName, Revoke methods
    - Define UpdateLastUsedAt and RevokeAllByUserID methods
    - Add mockery generate directive
    - _Requirements: 2.1, 2.5, 2.6, 3.4, 3.5, 3.6_

  - [ ] 2.3 Write unit tests for APIKey entity methods
    - Test IsExpired() with various expiration scenarios
    - Test IsValid() with combined status and expiration checks
    - _Requirements: 2.3, 2.4_

- [ ] 3. Implement infrastructure layer for API keys
  - [ ] 3.1 Create PostgreSQL repository implementation
    - Create `internal/infrastructure/database/postgres/apikey.go`
    - Implement NewAPIKeyRepository constructor
    - Implement Create method with INSERT query
    - Implement GetByHash method for authentication lookup
    - Implement GetByID method for revocation
    - Implement ListByUserID with pagination
    - Implement ListAll with username filter for admin view
    - Implement CountActiveByUserID for limit check
    - Implement ExistsActiveByName for duplicate check
    - Implement Revoke method to update status
    - Implement UpdateLastUsedAt for usage tracking
    - Implement RevokeAllByUserID for cascade revocation
    - _Requirements: 2.1, 2.2, 2.5, 2.6, 3.4, 3.5, 3.6_

  - [ ] 3.2 Write unit tests for PostgreSQL repository
    - Test Create with valid API key
    - Test GetByHash with existing and non-existing keys
    - Test ListByUserID pagination
    - Test CountActiveByUserID accuracy
    - Test Revoke status update
    - Use go-sqlmock for database mocking
    - _Requirements: 2.1, 2.2, 2.5_

- [ ] 4. Extend UserRepository with GetUserByID
  - [ ] 4.1 Add GetUserByID to UserRepository interface
    - Update `internal/domain/user/repository.go` with GetUserByID method
    - _Requirements: 4.3_

  - [ ] 4.2 Implement GetUserByID in PostgreSQL repository
    - Add GetUserByID implementation to `internal/infrastructure/database/postgres/user.go`
    - Return nil, nil when user not found (consistent with other methods)
    - _Requirements: 4.3_

  - [ ] 4.3 Regenerate UserRepository mock
    - Run `make generate` or mockery command for UserRepository
    - _Requirements: 4.3_

- [ ] 5. Checkpoint - Ensure domain and infrastructure layers compile
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Implement usecase layer for API key management
  - [ ] 6.1 Add API key constants and helper functions
    - Add APIKeyPrefix, APIKeyByteLen, MaxKeysPerUser, MaxExpiryDays constants to auth usecase
    - Implement validateKeyName function for name validation
    - _Requirements: 1.2, 1.5, 1.6, 1.7_

  - [ ] 6.2 Extend AuthUsecase interface with API key methods
    - Update `internal/usecase/user/usecase.go` interface definition
    - Add CreateAPIKey, ListAPIKeys, RevokeAPIKey, GetAPIKeyByID methods
    - _Requirements: 1.1, 2.5, 3.1, 3.2, 3.3_

  - [ ] 6.3 Update authUsecase struct with apiKeyRepo dependency
    - Add apiKeyRepo field to authUsecase struct
    - Update NewAuthUsecase constructor to accept APIKeyRepository
    - _Requirements: 1.1, 4.1_

  - [ ] 6.4 Implement CreateAPIKey method
    - Validate name using validateKeyName
    - Check for duplicate active name using ExistsActiveByName
    - Check max keys limit using CountActiveByUserID
    - Validate expiration date range (not past, not > 365 days)
    - Generate 32 bytes cryptographically secure random
    - Create plaintext with gtk_ prefix and base64 encoding
    - Compute SHA-256 hash for storage
    - Persist API key record
    - Return plaintext (once) and key metadata
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8_

  - [ ] 6.5 Implement ListAPIKeys method
    - For regular users: list own keys using ListByUserID
    - For admin: list all keys using ListAll with optional username filter
    - Return keys without key_hash field
    - Support pagination with limit and offset
    - _Requirements: 2.5, 6.1, 6.2, 6.5_

  - [ ] 6.6 Implement RevokeAPIKey method
    - Get key by ID using GetByID
    - Verify ownership or admin role
    - Call Revoke on repository
    - Delete session from Redis store if exists
    - _Requirements: 3.1, 3.2, 3.3, 3.7_

  - [ ] 6.7 Implement GetAPIKeyByID method
    - Simple wrapper around repository GetByID
    - _Requirements: 3.1_

  - [ ] 6.8 Write unit tests for CreateAPIKey
    - Test successful creation with valid inputs
    - Test rejection on duplicate name
    - Test rejection when max keys reached
    - Test rejection on invalid name formats
    - Test rejection on past expiration date
    - Test rejection on expiration > 365 days
    - _Requirements: 1.1, 1.4, 1.5, 1.7, 1.8_

  - [ ] 6.9 Write unit tests for RevokeAPIKey
    - Test owner revoking own key
    - Test admin revoking any key
    - Test non-owner non-admin rejection
    - _Requirements: 3.1, 3.2, 3.3_

- [ ] 7. Implement API key authentication in VerifyToken
  - [ ] 7.1 Implement verifyAPIKey internal method
    - Validate token format (must have content after gtk_ prefix)
    - Compute SHA-256 hash of token
    - Lookup key by hash using GetByHash
    - Check key validity (status active, not expired)
    - Lookup owner user using GetUserByID
    - Verify user is active (status = 1)
    - Update last_used_at asynchronously (non-blocking)
    - Register session in Redis for consistency
    - Return User entity on success
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

  - [ ] 7.2 Modify VerifyToken to route based on token prefix
    - Check if token starts with gtk_ prefix
    - Route to verifyAPIKey for API keys
    - Route to existing verifyJWT for JWT tokens
    - _Requirements: 4.1, 4.2_

  - [ ] 7.3 Write unit tests for verifyAPIKey
    - Test successful authentication with valid key
    - Test rejection on key not found
    - Test rejection on revoked key
    - Test rejection on expired key
    - Test rejection on inactive user
    - Test rejection on empty token after prefix
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [ ] 7.4 Write property test for API key format validity (Property 1)
    - **Property 1: API Key Format Validity**
    - Verify generated keys start with gtk_ and have minimum 47 characters
    - **Validates: Requirements 1.2, 1.6**

  - [ ] 7.5 Write property test for name validation rejection (Property 2)
    - **Property 2: Name Validation Rejection**
    - Verify invalid names (empty, >64 chars, invalid chars) are rejected
    - **Validates: Requirements 1.7**

  - [ ] 7.6 Write property test for expiration date validation (Property 3)
    - **Property 3: Expiration Date Validation**
    - Verify past dates and >365 days are rejected
    - **Validates: Requirements 1.4**

  - [ ] 7.7 Write property test for revoked key auth failure (Property 4)
    - **Property 4: Revoked Key Authentication Failure**
    - Verify revoked keys always fail authentication
    - **Validates: Requirements 2.4, 4.4**

  - [ ] 7.8 Write property test for expired key auth failure (Property 5)
    - **Property 5: Expired Key Authentication Failure**
    - Verify expired keys always fail authentication
    - **Validates: Requirements 2.3, 4.4**

- [ ] 8. Checkpoint - Ensure usecase layer tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Implement user cascade revocation
  - [ ] 9.1 Update user deletion to revoke API keys
    - Modify DeleteUser in auth usecase to call RevokeAllByUserID
    - Database CASCADE will handle table cleanup
    - _Requirements: 3.4_

  - [ ] 9.2 Update user deactivation to revoke API keys
    - Modify UpdateUserStatus in auth usecase
    - When status changes from active, call RevokeAllByUserID
    - _Requirements: 3.5_

  - [ ] 9.3 Update RevokeUserTokens to include API keys
    - Extend existing RevokeUserTokens to also revoke API keys
    - _Requirements: 3.6_

  - [ ] 9.4 Write property test for user state change cascade (Property 8)
    - **Property 8: User State Change Cascades to API Keys**
    - Verify user deletion/deactivation revokes all API keys
    - **Validates: Requirements 3.4, 3.5, 3.6**

- [ ] 10. Implement Web API handlers for token management
  - [ ] 10.1 Create TokenHandler struct
    - Create `internal/delivery/web/handler/token.go`
    - Define TokenHandler with template and authUsecase dependencies
    - Implement NewToken constructor
    - _Requirements: 6.1_

  - [ ] 10.2 Implement TokensPage handler
    - Render tokens.html template with user context
    - _Requirements: 6.1_

  - [ ] 10.3 Implement ListTokens API handler
    - Parse pagination parameters (limit, offset)
    - For admin: parse username filter parameter
    - Call ListAPIKeys usecase method
    - Return JSON response with keys (excluding hash)
    - _Requirements: 6.1, 6.2, 6.3, 6.5_

  - [ ] 10.4 Implement CreateToken API handler
    - Parse JSON request body (name, expires_at)
    - Parse expires_at as RFC3339 if provided
    - Call CreateAPIKey usecase method
    - Return JSON with plaintext key (once), id, name, timestamps
    - Handle specific error responses (400, 409)
    - _Requirements: 1.1, 6.4, 6.6, 6.8_

  - [ ] 10.5 Implement RevokeToken API handler
    - Parse key ID from URL path
    - Call RevokeAPIKey usecase method
    - Handle specific errors (404, 403)
    - Return success response
    - _Requirements: 3.1, 3.2, 3.3, 6.7_

  - [ ] 10.6 Write unit tests for TokenHandler
    - Test ListTokens pagination
    - Test CreateToken success and validation errors
    - Test RevokeToken with various scenarios
    - _Requirements: 6.1, 6.4, 6.7_

  - [ ] 10.7 Write property test for key hash exclusion (Property 6)
    - **Property 6: Key Hash Exclusion in Responses**
    - Verify no response contains key_hash field
    - **Validates: Requirements 2.5, 6.3**

  - [ ] 10.8 Write property test for ownership-based revocation (Property 7)
    - **Property 7: Ownership-Based Revocation Authorization**
    - Verify owner and admin can revoke, non-owner cannot
    - **Validates: Requirements 3.1, 3.2, 3.3**

- [ ] 11. Register Web API routes and update DI
  - [ ] 11.1 Register token routes in router
    - Add /tokens page route (GET) with JWT + CSRF middleware
    - Add /api/tokens routes (GET, POST) with JWT + CSRF middleware
    - Add /api/tokens/{id} route (DELETE) with JWT + CSRF middleware
    - _Requirements: 6.1_

  - [ ] 11.2 Update WebUI DI wiring
    - Add APIKeyRepository initialization in BuildWebUIApp
    - Update NewAuthUsecase call with apiKeyRepo parameter
    - Create TokenHandler and pass to router
    - _Requirements: 1.1, 6.1_

  - [ ] 11.3 Update Tunnel DI wiring
    - Add APIKeyRepository initialization in BuildTunnelApp
    - Update NewAuthUsecase call with apiKeyRepo parameter
    - _Requirements: 4.1_

- [ ] 12. Create Web UI template for token management
  - [ ] 12.1 Create tokens.html template
    - Create `assets/templates/tokens.html`
    - Add table for displaying API keys with columns: name, created_at, expires_at, last_used_at, status, actions
    - Add pagination controls
    - Add "Create New Token" button
    - Add revoke button with confirmation prompt
    - For admin: add owner username column and filter input
    - _Requirements: 6.1, 6.2, 6.5_

  - [ ] 12.2 Implement token creation modal
    - Add modal with form fields: name (text), expires_at (datetime)
    - Add validation feedback for name constraints
    - Add submit button to call POST /api/tokens
    - _Requirements: 6.4, 6.8_

  - [ ] 12.3 Implement plaintext key display modal
    - Display plaintext key after successful creation
    - Add copy-to-clipboard button
    - Add warning message about one-time display
    - Clear plaintext on modal close
    - _Requirements: 6.4_

  - [ ] 12.4 Add navigation link to tokens page
    - Update base.html or navigation component
    - Add "API Keys" or "Tokens" link in sidebar/menu
    - _Requirements: 6.1_

- [ ] 13. Checkpoint - Ensure Web UI works end-to-end
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. Implement CLI client API key support
  - [ ] 14.1 Add --token flag to CLI client
    - Update `cmd/client/main.go` flag definitions
    - Add tokenFlag for --token command line argument
    - _Requirements: 5.1_

  - [ ] 14.2 Implement GOTUNNEL_TOKEN environment variable support
    - Read GOTUNNEL_TOKEN from environment
    - Flag takes precedence over environment variable
    - _Requirements: 5.1_

  - [ ] 14.3 Implement token format validation
    - Validate token starts with gtk_ prefix
    - Print error and exit with code 1 if invalid format
    - _Requirements: 5.4_

  - [ ] 14.4 Implement token precedence logic
    - Direct token (flag or env) takes precedence over stored credential
    - If no token and no stored credential, print error and exit
    - _Requirements: 5.1, 5.2, 5.5_

  - [ ] 14.5 Update Client struct to accept token override
    - Modify NewClient in `internal/client/client.go`
    - Accept optional tokenOverride parameter
    - Override cfg.AuthToken when provided
    - _Requirements: 5.1, 5.2_

  - [ ] 14.6 Handle authentication failure exit
    - On server auth rejection, print error to stderr
    - Exit with code 1 without retry
    - _Requirements: 5.3_

  - [ ] 14.7 Write property test for CLI token format validation (Property 11)
    - **Property 11: CLI Token Format Validation**
    - Verify gtk_ tokens are used directly, non-gtk_ tokens cause error exit
    - Verify flag takes precedence over env variable
    - **Validates: Requirements 5.1, 5.2, 5.4**

- [ ] 15. Implement token routing in tunnel server
  - [ ] 15.1 Write property test for token routing (Property 10)
    - **Property 10: Token Routing Based on Prefix**
    - Verify gtk_ tokens route to API key path
    - Verify gtk_ with no content is rejected
    - Verify non-gtk_ tokens route to JWT path
    - **Validates: Requirements 4.1, 4.2**

  - [ ] 15.2 Write property test for valid API key returns correct user (Property 9)
    - **Property 9: Valid API Key Returns Correct User Entity**
    - Verify returned User entity matches key owner
    - **Validates: Requirements 4.3, 4.6**

- [ ] 16. Run database migration
  - [ ] 16.1 Apply migration to development database
    - Run `make migrate-up` or equivalent command
    - Verify api_keys table created with correct schema
    - Verify indexes created
    - _Requirements: 2.1_

- [ ] 17. Final checkpoint - Complete integration testing
  - Ensure all tests pass, ask the user if questions arise.
  - Verify end-to-end flow: create key in Web UI → use key in CLI → revoke key
  - Verify JWT authentication still works unchanged

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties defined in design document
- Unit tests validate specific examples and edge cases
- Design specifies Go language, so all implementation uses Go
- Database migration must be run before testing infrastructure layer
- Mock generation (`make generate`) should be run after adding new interfaces

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "2.2"] },
    { "id": 2, "tasks": ["2.3", "3.1", "4.1"] },
    { "id": 3, "tasks": ["3.2", "4.2"] },
    { "id": 4, "tasks": ["4.3"] },
    { "id": 5, "tasks": ["6.1", "6.2"] },
    { "id": 6, "tasks": ["6.3"] },
    { "id": 7, "tasks": ["6.4", "6.5", "6.6", "6.7"] },
    { "id": 8, "tasks": ["6.8", "6.9", "7.1"] },
    { "id": 9, "tasks": ["7.2"] },
    { "id": 10, "tasks": ["7.3", "7.4", "7.5", "7.6", "7.7", "7.8"] },
    { "id": 11, "tasks": ["9.1", "9.2", "9.3"] },
    { "id": 12, "tasks": ["9.4", "10.1"] },
    { "id": 13, "tasks": ["10.2", "10.3", "10.4", "10.5"] },
    { "id": 14, "tasks": ["10.6", "10.7", "10.8", "11.1", "11.2", "11.3"] },
    { "id": 15, "tasks": ["12.1"] },
    { "id": 16, "tasks": ["12.2", "12.3", "12.4"] },
    { "id": 17, "tasks": ["14.1", "14.2"] },
    { "id": 18, "tasks": ["14.3", "14.4"] },
    { "id": 19, "tasks": ["14.5", "14.6"] },
    { "id": 20, "tasks": ["14.7", "15.1", "15.2"] },
    { "id": 21, "tasks": ["16.1"] }
  ]
}
```
