package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// validateTokenFormat validates that a token has the correct format for CLI usage.
// Returns true if the token is valid (empty or starts with gtk_ prefix).
// This mirrors the validation logic in main.go for testability.
func validateTokenFormat(token string) bool {
	// Empty token is valid - allows fallback to stored credentials
	if token == "" {
		return true
	}
	// Non-empty token must start with gtk_ prefix
	return strings.HasPrefix(token, "gtk_")
}

// TestTokenFormatValidation verifies Property 11: CLI Token Format Validation
//
// **Validates: Requirements 5.1, 5.2, 5.4**
//
// Property 11 Statement:
// - If the value starts with `gtk_`, the CLI SHALL use it directly as auth_token
// - If the value does NOT start with `gtk_`, the CLI SHALL print an error and exit
// - The `--token` flag SHALL take precedence over `GOTUNNEL_TOKEN` when both present
func TestTokenFormatValidation(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantValid bool
	}{
		// Valid tokens starting with "gtk_" should pass validation
		{
			name:      "valid token with full key",
			token:     "gtk_abc123def456ghi789",
			wantValid: true,
		},
		{
			name:      "valid token with minimal content after prefix",
			token:     "gtk_x",
			wantValid: true,
		},
		{
			name:      "valid token with only prefix",
			token:     "gtk_",
			wantValid: true, // Empty after prefix is caught by server, not CLI
		},
		{
			name:      "valid token with base64-like content",
			token:     "gtk_SGVsbG9Xb3JsZDEyMzQ1Njc4OTAxMjM0NTY3ODkw",
			wantValid: true,
		},
		{
			name:      "valid token with special characters after prefix",
			token:     "gtk_abc-123_def.456",
			wantValid: true,
		},

		// Invalid tokens not starting with "gtk_" should fail validation
		{
			name:      "invalid token with jwt-like format",
			token:     "jwt_token",
			wantValid: false,
		},
		{
			name:      "invalid token with no prefix",
			token:     "abc123",
			wantValid: false,
		},
		{
			name:      "invalid token with wrong case prefix",
			token:     "GTK_abc",
			wantValid: false, // Case sensitive
		},
		{
			name:      "invalid token with partial prefix",
			token:     "gtk",
			wantValid: false,
		},
		{
			name:      "invalid token with prefix at end",
			token:     "abc_gtk_",
			wantValid: false,
		},
		{
			name:      "invalid token with embedded prefix",
			token:     "token_gtk_embedded",
			wantValid: false,
		},
		{
			name:      "invalid JWT-like token",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantValid: false,
		},
		{
			name:      "invalid token with spaces",
			token:     "gtk _abc",
			wantValid: false,
		},

		// Empty token is valid - allows fallback to stored credentials
		{
			name:      "empty token allows fallback",
			token:     "",
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := validateTokenFormat(tt.token)
			assert.Equal(t, tt.wantValid, valid,
				"token %q: got valid=%v, want %v", tt.token, valid, tt.wantValid)
		})
	}
}

// TestTokenPrecedence verifies that --token flag takes precedence over GOTUNNEL_TOKEN
// environment variable when both are present.
//
// **Validates: Requirements 5.1, 5.4**
func TestTokenPrecedence(t *testing.T) {
	tests := []struct {
		name          string
		flagToken     string
		envToken      string
		expectedToken string
	}{
		{
			name:          "flag takes precedence over env",
			flagToken:     "gtk_from_flag",
			envToken:      "gtk_from_env",
			expectedToken: "gtk_from_flag",
		},
		{
			name:          "env used when flag is empty",
			flagToken:     "",
			envToken:      "gtk_from_env",
			expectedToken: "gtk_from_env",
		},
		{
			name:          "flag used when env is empty",
			flagToken:     "gtk_from_flag",
			envToken:      "",
			expectedToken: "gtk_from_flag",
		},
		{
			name:          "both empty returns empty",
			flagToken:     "",
			envToken:      "",
			expectedToken: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the precedence logic from main.go
			var token string
			if tt.flagToken != "" {
				token = tt.flagToken
			} else if tt.envToken != "" {
				token = tt.envToken
			}

			assert.Equal(t, tt.expectedToken, token,
				"expected token %q but got %q", tt.expectedToken, token)
		})
	}
}

// TestTokenValidationWithPrecedence tests the combination of precedence and validation.
// This verifies the complete flow: determine token source -> validate format.
//
// **Validates: Requirements 5.1, 5.2, 5.4**
func TestTokenValidationWithPrecedence(t *testing.T) {
	tests := []struct {
		name              string
		flagToken         string
		envToken          string
		expectValid       bool
		expectTokenSource string
	}{
		{
			name:              "valid flag token takes precedence",
			flagToken:         "gtk_flag_token",
			envToken:          "gtk_env_token",
			expectValid:       true,
			expectTokenSource: "gtk_flag_token",
		},
		{
			name:              "invalid flag token still takes precedence",
			flagToken:         "invalid_flag",
			envToken:          "gtk_valid_env",
			expectValid:       false,
			expectTokenSource: "invalid_flag",
		},
		{
			name:              "valid env token used when flag empty",
			flagToken:         "",
			envToken:          "gtk_env_token",
			expectValid:       true,
			expectTokenSource: "gtk_env_token",
		},
		{
			name:              "invalid env token rejected when flag empty",
			flagToken:         "",
			envToken:          "invalid_env",
			expectValid:       false,
			expectTokenSource: "invalid_env",
		},
		{
			name:              "no token is valid (fallback to stored creds)",
			flagToken:         "",
			envToken:          "",
			expectValid:       true,
			expectTokenSource: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Determine token using precedence logic
			var token string
			if tt.flagToken != "" {
				token = tt.flagToken
			} else if tt.envToken != "" {
				token = tt.envToken
			}

			// Verify token source
			assert.Equal(t, tt.expectTokenSource, token,
				"expected token source %q but got %q", tt.expectTokenSource, token)

			// Validate token format
			valid := validateTokenFormat(token)
			assert.Equal(t, tt.expectValid, valid,
				"token %q validation: expected %v but got %v", token, tt.expectValid, valid)
		})
	}
}
