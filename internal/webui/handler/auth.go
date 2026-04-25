package handler

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtCookieName = "tunnel_token"
	jwtSecret     = "very-secret-key-change-me" // hardcoded as requested
	adminUser     = "admin"
	adminPass     = "admin123"
)

// AuthHandler handles login and session management.
type AuthHandler struct {
	tmpl *template.Template
}

func NewAuth(fs embed.FS) *AuthHandler {
	tmpl := template.Must(template.ParseFS(fs,
		"templates/base.html",
		"templates/login.html",
	))
	return &AuthHandler{tmpl: tmpl}
}

func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	_ = h.tmpl.ExecuteTemplate(w, "base", nil)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("username")
	pass := r.FormValue("password")

	if user != adminUser || pass != adminPass {
		_ = h.tmpl.ExecuteTemplate(w, "base", map[string]string{
			"Error": "Invalid username or password",
		})
		return
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieName,
		Value:    tokenString,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Middleware handles JWT validation
func JWTMiddleware(next http.Handler) http.Handler {
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

		next.ServeHTTP(w, r)
	})
}
