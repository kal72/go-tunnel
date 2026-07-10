package handler

import (
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"time"

	domainErrors "gotunnel/internal/domain/errors"
	usecaseUser "gotunnel/internal/usecase/user"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// TokenHandler handles token (API key) management endpoints.
type TokenHandler struct {
	tmpl        *template.Template
	authUsecase usecaseUser.AuthUsecase
}

// NewToken creates a new TokenHandler with the given template filesystem and auth usecase.
func NewToken(fs embed.FS, authUsecase usecaseUser.AuthUsecase) *TokenHandler {
	tmpl := template.Must(template.ParseFS(fs,
		"templates/base.html",
		"templates/tokens.html",
	))
	return &TokenHandler{
		tmpl:        tmpl,
		authUsecase: authUsecase,
	}
}

// TokensPage renders the token management page.
func (h *TokenHandler) TokensPage(w http.ResponseWriter, r *http.Request) {
	userRole := r.Context().Value(UserRoleKey).(int16)
	username := r.Context().Value(UserNameKey).(string)
	csrf, _ := r.Context().Value(CSRFTokenKey).(string)

	_ = h.tmpl.ExecuteTemplate(w, "base", map[string]any{
		"Page":          "tokens",
		"UserRole":      userRole,
		"UserName":      username,
		"CSRFToken":     csrf,
		"DomainEnabled": true,
	})
}

// ListTokens returns a list of API keys for the current user or all users (admin).
func (h *TokenHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Context().Value(UserIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)
	userRole := r.Context().Value(UserRoleKey).(int16)

	// Parse pagination parameters
	limit := 50 // default
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// For admin: parse username filter
	usernameFilter := ""
	if userRole == 1 {
		usernameFilter = r.URL.Query().Get("username")
	}

	keys, total, err := h.authUsecase.ListAPIKeys(r.Context(), userID, userRole, limit, offset, usernameFilter)
	if err != nil {
		http.Error(w, `{"error":"failed to list tokens"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys":   keys,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// CreateToken creates a new API key.
func (h *TokenHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Context().Value(UserIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)

	var req struct {
		ExpiresAt *string `json:"expires_at,omitempty"`
		Name      string  `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			http.Error(w, `{"error":"invalid expires_at format, use RFC3339"}`, http.StatusBadRequest)
			return
		}
		expiresAt = &t
	}

	plaintext, key, err := h.authUsecase.CreateAPIKey(r.Context(), userID, req.Name, expiresAt)
	if err != nil {
		// Map errors to appropriate HTTP status codes
		if errors.Is(err, domainErrors.ErrAlreadyExists) {
			http.Error(w, `{"error":"an active key with this name already exists"}`, http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"key":        plaintext,
		"id":         key.ID,
		"name":       key.Name,
		"expires_at": key.ExpiresAt,
		"created_at": key.CreatedAt,
	})
}

// RevokeToken revokes an API key by ID.
func (h *TokenHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Context().Value(UserIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)
	userRole := r.Context().Value(UserRoleKey).(int16)

	// Parse key ID from URL path
	keyIDStr := chi.URLParam(r, "id")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		http.Error(w, `{"error":"invalid key ID"}`, http.StatusBadRequest)
		return
	}

	err = h.authUsecase.RevokeAPIKey(r.Context(), keyID, userID, userRole)
	if err != nil {
		if errors.Is(err, domainErrors.ErrNotFound) {
			http.Error(w, `{"error":"API key not found"}`, http.StatusNotFound)
			return
		}
		if errors.Is(err, domainErrors.ErrForbidden) {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "API key revoked successfully",
	})
}
