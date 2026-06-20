package handler

import (
	"embed"
	"encoding/json"
	"github.com/google/uuid"
	"gotunnel/internal/tunnel/state"
	"gotunnel/internal/webui/model"
	"html/template"
	"math/rand"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

type Handler struct {
	dashTmpl       *template.Template
	confTmpl       *template.Template
	domainTmpl     *template.Template
	docsTmpl       *template.Template
	downTmpl       *template.Template
	store          state.Store
	domainStore    state.Store
	configRepo     state.ConfigRepository
	masterSecret   string
	tunnelAddr     string
	wildcardDomain string
	gatewayHost    string
}

// New creates a Handler and parses embedded HTML templates.
func New(fs embed.FS, store state.Store, domainStore state.Store, configRepo state.ConfigRepository, masterSecret string, tunnelAddr string, wildcardDomain string, gatewayHost string) *Handler {
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

	downTmpl := template.Must(template.New("base").Funcs(funcMap).ParseFS(fs,
		"templates/base.html",
		"templates/downloads.html",
	))

	return &Handler{
		dashTmpl:       dashTmpl,
		confTmpl:       confTmpl,
		domainTmpl:     domainTmpl,
		docsTmpl:       docsTmpl,
		downTmpl:       downTmpl,
		store:          store,
		domainStore:    domainStore,
		configRepo:     configRepo,
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

	role, _ := r.Context().Value(UserRoleKey).(int16)
	username, _ := r.Context().Value(UserNameKey).(string)

	data := map[string]any{
		"Tunnels":        tunnels,
		"DomainEnabled":  h.wildcardDomain != "",
		"TunnelAddr":     h.tunnelAddr,
		"WildcardDomain": h.wildcardDomain,
		"UserRole":       role,
		"UserName":       username,
	}

	if err := h.dashTmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Downloads renders the client downloads page.
func (h *Handler) Downloads(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(UserRoleKey).(int16)
	username, _ := r.Context().Value(UserNameKey).(string)

	data := map[string]any{
		"DomainEnabled":  h.wildcardDomain != "",
		"UserRole":       role,
		"UserName":       username,
	}
	if err := h.downTmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Domains renders the domain management page.
func (h *Handler) Domains(w http.ResponseWriter, r *http.Request) {
	if h.wildcardDomain == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	role, _ := r.Context().Value(UserRoleKey).(int16)
	username, _ := r.Context().Value(UserNameKey).(string)
	data := map[string]any{
		"DomainEnabled":  true,
		"WildcardDomain": h.wildcardDomain,
		"GatewayHost":    h.gatewayHost,
		"UserRole":       role,
		"UserName":       username,
	}
	if err := h.domainTmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Docs renders the documentation page.
func (h *Handler) Docs(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(UserRoleKey).(int16)
	username, _ := r.Context().Value(UserNameKey).(string)
	data := map[string]any{
		"TunnelAddr":    h.tunnelAddr,
		"DomainEnabled": h.wildcardDomain != "",
		"UserRole":      role,
		"UserName":      username,
		"HideSidebar":   true,
	}
	if err := h.docsTmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Configs renders the main config manager page.
func (h *Handler) Configs(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(UserRoleKey).(int16)
	username, _ := r.Context().Value(UserNameKey).(string)

	if err := h.confTmpl.ExecuteTemplate(w, "base", map[string]any{
		"TunnelAddr":    h.tunnelAddr,
		"DomainEnabled": h.wildcardDomain != "",
		"UserRole":      role,
		"UserName":      username,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ListConfigs returns all configs based on user role.
func (h *Handler) ListConfigs(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(UserRoleKey).(int16)
	userID, _ := r.Context().Value(UserIDKey).(string)
	uid, _ := uuid.Parse(userID)

	var configs []state.ClientConfig
	var err error

	if role == 1 {
		configs, err = h.configRepo.GetAllConfigs(r.Context())
	} else {
		configs, err = h.configRepo.GetConfigsByUserID(r.Context(), uid)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, configs)
}

// GetConfig returns a config by id.
func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	cfg, err := h.configRepo.GetConfigByID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cfg == nil {
		http.Error(w, "config not found", http.StatusNotFound)
		return
	}

	role, _ := r.Context().Value(UserRoleKey).(int16)
	userID, _ := r.Context().Value(UserIDKey).(string)
	uid, _ := uuid.Parse(userID)

	if role != 1 && cfg.UserID != uid {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	writeJSON(w, cfg)
}

// CreateConfig creates a new configuration.
func (h *Handler) CreateConfig(w http.ResponseWriter, r *http.Request) {
	var payload state.ClientConfig
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if payload.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	userID, _ := r.Context().Value(UserIDKey).(string)
	uid, _ := uuid.Parse(userID)

	cfg := &state.ClientConfig{
		ID:      uuid.New(),
		UserID:  uid,
		Name:    payload.Name,
		Tunnels: payload.Tunnels,
	}

	if err := h.configRepo.CreateConfig(r.Context(), cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"status": "ok", "config": cfg})
}

// UpdateConfig updates an existing configuration.
func (h *Handler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	cfg, err := h.configRepo.GetConfigByID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cfg == nil {
		http.Error(w, "config not found", http.StatusNotFound)
		return
	}

	role, _ := r.Context().Value(UserRoleKey).(int16)
	userID, _ := r.Context().Value(UserIDKey).(string)
	uid, _ := uuid.Parse(userID)

	if role != 1 && cfg.UserID != uid {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var payload state.ClientConfig
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	cfg.Name = payload.Name
	cfg.Tunnels = payload.Tunnels

	if err := h.configRepo.UpdateConfig(r.Context(), cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"status": "ok", "config": cfg})
}

// DeleteConfig deletes a configuration.
func (h *Handler) DeleteConfig(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	cfg, err := h.configRepo.GetConfigByID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cfg == nil {
		http.Error(w, "config not found", http.StatusNotFound)
		return
	}

	role, _ := r.Context().Value(UserRoleKey).(int16)
	userID, _ := r.Context().Value(UserIDKey).(string)
	uid, _ := uuid.Parse(userID)

	if role != 1 && cfg.UserID != uid {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := h.configRepo.DeleteConfig(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "ok", "message": "config deleted"})
}

// Client API Handlers

// ClientGetConfigs returns a list of config names for the CLI.
func (h *Handler) ClientGetConfigs(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(UserIDKey).(string)
	uid, _ := uuid.Parse(userID)

	configs, err := h.configRepo.GetConfigsByUserID(r.Context(), uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var names []string
	for _, c := range configs {
		names = append(names, c.Name)
	}

	writeJSON(w, names)
}

// ClientGetConfig returns the ClientConfig payload for the CLI.
func (h *Handler) ClientGetConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	userID, _ := r.Context().Value(UserIDKey).(string)
	uid, _ := uuid.Parse(userID)

	cfg, err := h.configRepo.GetConfigByName(r.Context(), uid, name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cfg == nil {
		http.Error(w, "config not found", http.StatusNotFound)
		return
	}

	// Transform to model.ClientConfig format that the client binary expects
	var tunnels []model.TunnelEntry
	for _, t := range cfg.Tunnels {
		tunnels = append(tunnels, model.TunnelEntry{
			Hostname: t.Hostname,
			Target:   t.Target,
			Mode:     t.Mode,
		})
	}

	// We pass the JWT token itself back to the client as the AuthToken?
	// The client already HAS the token because it sent it via Authorization.
	// But let's construct the payload.
	clientConfig := model.ClientConfig{
		TunnelAddr:    h.tunnelAddr,
		SkipTLSVerify: false,
		ClientID:      cfg.ID.String(),
		AuthToken:     "", // Client uses its own JWT
		Tunnels:       tunnels,
	}

	writeJSON(w, clientConfig)
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
