package webui

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"gotunnel/internal/model"
	"gotunnel/internal/usecase"
)

const (
	jwtCookieName = "tunnel_token"
)

type contextKey string

const (
	UserRoleKey contextKey = "user_role"
	UserNameKey contextKey = "user_name"
	UserIDKey   contextKey = "user_id"
)

// AuthHandler handles login and session management.
type AuthHandler struct {
	tmpl        *template.Template
	authUsecase usecase.AuthUsecase
}

func NewAuth(fs embed.FS, authUsecase usecase.AuthUsecase) *AuthHandler {
	tmpl := template.Must(template.ParseFS(fs,
		"templates/base.html",
		"templates/login.html",
	))
	return &AuthHandler{
		tmpl:        tmpl,
		authUsecase: authUsecase,
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

	tokenString, err := h.authUsecase.Login(r.Context(), userStr, passStr)
	if err != nil {
		_ = h.tmpl.ExecuteTemplate(w, "base", map[string]any{
			"HideSidebar": true,
			"Error":       "Invalid username or password",
		})
		return
	}

	// Set cookie
	expiration := 24 * time.Hour
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
		_ = h.authUsecase.Logout(r.Context(), cookie.Value)
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

		user, err := h.authUsecase.VerifyToken(r.Context(), cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, UserRoleKey, user.Role)
		ctx = context.WithValue(ctx, UserNameKey, user.Username)
		ctx = context.WithValue(ctx, UserIDKey, user.ID.String())
		r = r.WithContext(ctx)

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

	tokenString, err := h.authUsecase.Login(r.Context(), userStr, passStr)
	if err != nil {
		if err == model.ErrUnauthorized {
			http.Error(w, "Invalid credentials or inactive account", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Failed to login", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"token":"%s"}`, tokenString)
}
