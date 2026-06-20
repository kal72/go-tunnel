package handler

import (
	"context"
	"embed"
	"fmt"
	"gotunnel/internal/tunnel/state"
	"html/template"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtCookieName = "tunnel_token"
	jwtSecret = "very-secret-key-change-me" // hardcoded as requested
)

type contextKey string

const (
	UserRoleKey contextKey = "user_role"
	UserNameKey contextKey = "user_name"
	UserIDKey   contextKey = "user_id"
)

// AuthHandler handles login and session management.
type AuthHandler struct {
	tmpl     *template.Template
	store    state.Store
	userRepo state.UserRepository
}

func NewAuth(fs embed.FS, store state.Store, userRepo state.UserRepository) *AuthHandler {
	tmpl := template.Must(template.ParseFS(fs,
		"templates/base.html",
		"templates/login.html",
	))
	return &AuthHandler{
		tmpl:     tmpl,
		store:    store,
		userRepo: userRepo,
	}
}

func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	_ = h.tmpl.ExecuteTemplate(w, "base", map[string]any{
		"HideSidebar": true,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	userStr := r.FormValue("username")
	passStr := r.FormValue("password")

	u, err := h.userRepo.GetUserByUsername(r.Context(), userStr)
	if err != nil || u == nil {
		_ = h.tmpl.ExecuteTemplate(w, "base", map[string]any{
			"HideSidebar": true,
			"Error":       "Invalid username or password",
		})
		return
	}

	if u.Status != 1 {
		_ = h.tmpl.ExecuteTemplate(w, "base", map[string]any{
			"HideSidebar": true,
			"Error":       "Account is inactive",
		})
		return
	}

	if !state.CheckPasswordHash(passStr, u.Password) {
		_ = h.tmpl.ExecuteTemplate(w, "base", map[string]any{
			"HideSidebar": true,
			"Error":       "Invalid username or password",
		})
		return
	}

	// Generate JWT
	expiration := 24 * time.Hour
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  u.ID.String(),
		"user": userStr,
		"role": u.Role,
		"exp":  time.Now().Add(expiration).Unix(),
	})

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	// Save token to Redis
	err = h.store.SetToken(r.Context(), tokenString, expiration)
	if err != nil {
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieName,
		Value:    tokenString,
		Path:     "/",
		Expires:  time.Now().Add(expiration),
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(jwtCookieName)
	if err == nil {
		// Revoke token in Redis
		_ = h.store.RevokeToken(r.Context(), cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// JWTMiddleware handles JWT validation and revocation check
func (h *AuthHandler) JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow login page and assets
		if r.URL.Path == "/login" || r.URL.Path == "/static" {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(jwtCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check if token is revoked in Redis
		revoked, err := h.store.IsTokenRevoked(r.Context(), cookie.Value)
		if err != nil || revoked {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			ctx := r.Context()
			if roleFloat, ok := claims["role"].(float64); ok {
				ctx = context.WithValue(ctx, UserRoleKey, int16(roleFloat))
			}
			if userStr, ok := claims["user"].(string); ok {
				ctx = context.WithValue(ctx, UserNameKey, userStr)
			}
			if subStr, ok := claims["sub"].(string); ok {
				ctx = context.WithValue(ctx, UserIDKey, subStr)
			}
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// APILogin handles CLI login to get a 30-day JWT.
func (h *AuthHandler) APILogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userStr := r.FormValue("username")
	passStr := r.FormValue("password")

	u, err := h.userRepo.GetUserByUsername(r.Context(), userStr)
	if err != nil || u == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if u.Status != 1 {
		http.Error(w, "Account inactive", http.StatusForbidden)
		return
	}

	if !state.CheckPasswordHash(passStr, u.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// 30 days token for CLI
	expiration := 30 * 24 * time.Hour
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  u.ID.String(),
		"user": userStr,
		"role": u.Role,
		"exp":  time.Now().Add(expiration).Unix(),
	})

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Save token to Redis (for revocation check)
	err = h.store.SetToken(r.Context(), tokenString, expiration)
	if err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"token":"%s"}`, tokenString)
}
