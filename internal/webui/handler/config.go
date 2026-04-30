package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"gotunnel/internal/tunnel/state"
	"gotunnel/internal/webui/model"
	"gotunnel/internal/webui/service"

	"html/template"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

type Handler struct {
	dashTmpl       *template.Template
	confTmpl       *template.Template
	domainTmpl     *template.Template
	docsTmpl       *template.Template
	store          state.Store
	domainStore    state.Store
	masterSecret   string
	tunnelAddr     string
	wildcardDomain string
	gatewayHost    string
}

// New creates a Handler and parses embedded HTML templates.
func New(fs embed.FS, store state.Store, domainStore state.Store, masterSecret string, tunnelAddr string, wildcardDomain string, gatewayHost string) *Handler {
	funcMap := template.FuncMap{
		"split": strings.Split,
	}

	dashTmpl := template.Must(template.New("base").Funcs(funcMap).ParseFS(fs,
		"templates/base.html",
		"templates/dashboard.html",
	))

	confTmpl := template.Must(template.New("base").Funcs(funcMap).ParseFS(fs,
		"templates/base.html",
		"templates/index.html",
	))

	domainTmpl := template.Must(template.New("base").Funcs(funcMap).ParseFS(fs,
		"templates/base.html",
		"templates/domains.html",
	))

	docsTmpl := template.Must(template.New("base").Funcs(funcMap).ParseFS(fs,
		"templates/base.html",
		"templates/docs.html",
	))

	return &Handler{
		dashTmpl:       dashTmpl,
		confTmpl:       confTmpl,
		domainTmpl:     domainTmpl,
		docsTmpl:       docsTmpl,
		store:          store,
		domainStore:    domainStore,
		masterSecret:   masterSecret,
		tunnelAddr:     tunnelAddr,
		wildcardDomain: wildcardDomain,
		gatewayHost:    gatewayHost,
	}
}

// Index renders the dashboard page.
func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	var tunnels []map[string]any

	if h.store != nil {
		infos, err := h.store.ListTunnels(r.Context())
		if err == nil {
			for _, info := range infos {
				tunnels = append(tunnels, map[string]any{
					"ClientID":    info.ClientID,
					"Client":      info.Client,
					"Hosts":       strings.Join(info.Hosts, ", "),
					"ConnectedAt": info.ConnectedAt.Format("01-02-2006 15:04:05"),
					"LastPing":    info.LastPing.Format("15:04:05"),
				})
			}
		}
	}

	data := map[string]any{
		"Tunnels":        tunnels,
		"DomainEnabled":  h.wildcardDomain != "",
		"TunnelAddr":     h.tunnelAddr,
		"WildcardDomain": h.wildcardDomain,
	}

	if err := h.dashTmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Domains renders the domain management page.
func (h *Handler) Domains(w http.ResponseWriter, r *http.Request) {
	if h.wildcardDomain == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	data := map[string]any{
		"DomainEnabled":  true,
		"WildcardDomain": h.wildcardDomain,
		"GatewayHost":    h.gatewayHost,
	}
	if err := h.domainTmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Docs renders the documentation page.
func (h *Handler) Docs(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"TunnelAddr":    h.tunnelAddr,
		"DomainEnabled": h.wildcardDomain != "",
	}
	if err := h.docsTmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Configs renders the main config manager page.
func (h *Handler) Configs(w http.ResponseWriter, r *http.Request) {
	configs, err := service.ListConfigs()
	if err != nil {
		http.Error(w, "failed to list configs", http.StatusInternalServerError)
		return
	}
	if err := h.confTmpl.ExecuteTemplate(w, "base", map[string]any{
		"Configs":       configs,
		"TunnelAddr":    h.tunnelAddr,
		"DomainEnabled": h.wildcardDomain != "",
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ListConfigs returns all available config file names as JSON.
func (h *Handler) ListConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := service.ListConfigs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, configs)
}

// GetConfig reads and returns a YAML config as JSON.
func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	data, err := service.ReadConfig(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, data)
}

// UpdateConfig accepts a typed JSON payload (ClientConfig),
// converts it to a YAML-serialisable map, and writes to disk.
// After successful write, it saves the auth_token to Redis.
func (h *Handler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var cfg model.ClientConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "invalid payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Round-trip through yaml marshal → unmarshal to get a clean map
	// preserving YAML field names defined via struct tags.
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		http.Error(w, "marshal error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var asMap map[string]any
	if err := yaml.Unmarshal(raw, &asMap); err != nil {
		http.Error(w, "unmarshal error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := service.WriteConfig(name, asMap); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Save the auth_token to Redis if present
	if cfg.AuthToken != "" && h.store != nil {
		// Valid for 1 year by default, or until revoked
		err := h.store.SetToken(r.Context(), cfg.AuthToken, 365*24*time.Hour)
		if err != nil {
			// Log error but don't fail the request as config is already saved
			fmt.Printf("Warning: failed to save token to redis: %v\n", err)
		}
	}

	writeJSON(w, map[string]string{"status": "ok", "config": name + ".yaml"})
}

func (h *Handler) DownloadConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	data, err := service.ReadConfigRaw(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	filename := name + ".yaml"
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Write(data)
}

// GenerateToken generates an HMAC authtoken for a given client_id.
// It NO LONGER saves it to Redis; that happens during UpdateConfig.
func (h *Handler) GenerateToken(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		http.Error(w, "client_id required", http.StatusBadRequest)
		return
	}

	mac := hmac.New(sha256.New, []byte(h.masterSecret))
	mac.Write([]byte(clientID))
	token := fmt.Sprintf("%x", mac.Sum(nil))

	writeJSON(w, map[string]string{"token": token, "client_id": clientID})
}

// RevokeToken removes a token from Redis.
func (h *Handler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}

	err := h.store.RevokeToken(r.Context(), token)
	if err != nil {
		http.Error(w, "failed to revoke token", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "ok", "message": "token revoked"})
}

// CreateConfig creates a new configuration file.
func (h *Handler) CreateConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	// Basic validation for filename
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}

	if err := service.CreateConfig(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "ok", "config": name})
}

// DeleteConfig removes a config file and revokes its token.
func (h *Handler) DeleteConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	// 1. Read config to get the token
	cfg, err := service.ReadConfig(name)
	if err == nil {
		// 2. Revoke token if it exists
		if token, ok := cfg["auth_token"].(string); ok && token != "" && h.store != nil {
			_ = h.store.RevokeToken(r.Context(), token)
		}
	}

	// 3. Delete the file
	if err := service.DeleteConfig(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "ok", "message": "config deleted and token revoked"})
}

// ListDomains returns all domains from Redis.
func (h *Handler) ListDomains(w http.ResponseWriter, r *http.Request) {
	if h.wildcardDomain == "" {
		http.Error(w, "Domain management is disabled (WILDCARD_DOMAIN is empty)", http.StatusForbidden)
		return
	}
	if h.domainStore == nil {
		writeJSON(w, []any{})
		return
	}
	domains, err := h.domainStore.ListDomains(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"domains":         domains,
		"wildcard_domain": h.wildcardDomain,
	})
}

// AddDomain adds a new domain to Redis.
func (h *Handler) AddDomain(w http.ResponseWriter, r *http.Request) {
	if h.wildcardDomain == "" {
		http.Error(w, "Domain management is disabled", http.StatusForbidden)
		return
	}
	if h.domainStore == nil {
		http.Error(w, "domain store not configured", http.StatusInternalServerError)
		return
	}
	var payload struct {
		Prefix string `json:"prefix"`
		Random bool   `json:"random"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	prefix := strings.TrimSpace(strings.ToLower(payload.Prefix))
	if payload.Random {
		prefix = generateRandomString(16)
	}

	if prefix == "" {
		http.Error(w, "prefix required", http.StatusBadRequest)
		return
	}

	// Validate prefix/domain
	for _, char := range prefix {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' || char == '.') {
			http.Error(w, "invalid characters in domain", http.StatusBadRequest)
			return
		}
	}

	fullDomain := prefix
	// If it doesn't contain a dot, treat it as a prefix for the wildcard domain
	if !strings.Contains(prefix, ".") && h.wildcardDomain != "" {
		base := strings.TrimPrefix(h.wildcardDomain, "*.")
		if base != "" {
			fullDomain = prefix + "." + base
		}
	}

	if err := h.domainStore.AddDomain(r.Context(), fullDomain); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "domain": fullDomain})
}

// RemoveDomain removes a domain from Redis.
func (h *Handler) RemoveDomain(w http.ResponseWriter, r *http.Request) {
	if h.domainStore == nil {
		http.Error(w, "domain store not configured", http.StatusInternalServerError)
		return
	}
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}

	if err := h.domainStore.RemoveDomain(r.Context(), domain); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "message": "domain removed"})
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		ret[i] = letters[rand.Intn(len(letters))]
	}
	return string(ret)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
