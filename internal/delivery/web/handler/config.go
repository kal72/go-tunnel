package handler

import (
	"embed"
	"encoding/json"
	domainConfig "gotunnel/internal/domain/config"
	usecaseConfig "gotunnel/internal/usecase/config"
	usecaseSetting "gotunnel/internal/usecase/setting"
	usecaseTunnel "gotunnel/internal/usecase/tunnel"
	"html/template"
	"net/http"
	"strings"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"

	"github.com/go-chi/chi/v5"
)

type Handler struct {
	dashTmpl       *template.Template
	confTmpl       *template.Template
	domainTmpl     *template.Template
	docsTmpl       *template.Template
	downTmpl       *template.Template
	tunnelUsecase  usecaseTunnel.TunnelUsecase
	configUsecase  usecaseConfig.ConfigUsecase
	settingUsecase usecaseSetting.SettingUsecase
	settingTmpl    *template.Template
	masterSecret   string
	tunnelAddr     string
	wildcardDomain string
	gatewayDomain  string
	acmeEnable       bool
	maxFreeDomains   int
	cliLatestVersion string
}

// New creates a Handler and parses embedded HTML templates.
func New(fs embed.FS, tunnelUsecase usecaseTunnel.TunnelUsecase, configUsecase usecaseConfig.ConfigUsecase, settingUsecase usecaseSetting.SettingUsecase, masterSecret string, tunnelAddr string, wildcardDomain string, gatewayDomain string, acmeEnable bool, maxFreeDomains int, cliLatestVersion string) *Handler {
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

	settingTmpl := template.Must(template.New("base").Funcs(funcMap).ParseFS(fs,
		"templates/base.html",
		"templates/settings.html",
	))

	return &Handler{
		dashTmpl:       dashTmpl,
		confTmpl:       confTmpl,
		domainTmpl:     domainTmpl,
		docsTmpl:       docsTmpl,
		downTmpl:       downTmpl,
		settingTmpl:    settingTmpl,
		tunnelUsecase:  tunnelUsecase,
		configUsecase:  configUsecase,
		settingUsecase: settingUsecase,
		masterSecret:   masterSecret,
		tunnelAddr:     tunnelAddr,
		wildcardDomain: wildcardDomain,
		gatewayDomain:  gatewayDomain,
		acmeEnable:       acmeEnable,
		maxFreeDomains:   maxFreeDomains,
		cliLatestVersion: cliLatestVersion,
	}
}

// Index renders the dashboard page.
func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	var tunnels []map[string]any

	if h.tunnelUsecase != nil {
		infos, err := h.tunnelUsecase.ListTunnels(r.Context())
		if err == nil {
			for _, info := range infos {
				tunnels = append(tunnels, map[string]any{
					"TunnelName":  info.Name,
					"ClientName":  info.ClientName,
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
		"DomainEnabled":    h.wildcardDomain != "",
		"UserRole":         role,
		"UserName":         username,
		"CLILatestVersion": h.cliLatestVersion,
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
		"GatewayDomain":  h.gatewayDomain,
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
		"GatewayDomain": h.gatewayDomain,
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

	var configs []domainConfig.ClientConfig
	var err error

	if role == 1 {
		configs, err = h.configUsecase.GetAllConfigs(r.Context())
	} else {
		configs, err = h.configUsecase.GetConfigsByUserID(r.Context(), uid)
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

	cfg, err := h.configUsecase.GetConfigByID(r.Context(), id)
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
	var payload domainConfig.ClientConfig
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

	if err := h.configUsecase.CreateConfig(r.Context(), uid, payload.Name, payload.Tunnels); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"status": "ok"})
}

// UpdateConfig updates an existing configuration.
func (h *Handler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	cfg, err := h.configUsecase.GetConfigByID(r.Context(), id)
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

	var payload domainConfig.ClientConfig
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if err := h.configUsecase.UpdateConfig(r.Context(), id, payload.Name, payload.Tunnels); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"status": "ok"})
}

// DeleteConfig deletes a configuration.
func (h *Handler) DeleteConfig(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	cfg, err := h.configUsecase.GetConfigByID(r.Context(), id)
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

	if err := h.configUsecase.DeleteConfig(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "ok", "message": "config deleted"})
}

// Domain and other handlers follow.

// ListDomains returns all domains from Redis.
func (h *Handler) ListDomains(w http.ResponseWriter, r *http.Request) {
	if h.wildcardDomain == "" {
		http.Error(w, "Domain management is disabled (WILDCARD_DOMAIN is empty)", http.StatusForbidden)
		return
	}
	if h.tunnelUsecase == nil {
		writeJSON(w, []any{})
		return
	}

	userIDStr, _ := r.Context().Value(UserIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)
	role, _ := r.Context().Value(UserRoleKey).(int16)

	domains, err := h.tunnelUsecase.ListDomains(r.Context(), userID, role)
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
	if h.tunnelUsecase == nil {
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
		var err error
		prefix, err = generateSubdomain()
		if err != nil {
			http.Error(w, "failed to generate random subdomain", http.StatusInternalServerError)
			return
		}
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
	isFreeDomain := false
	if !strings.Contains(prefix, ".") && h.wildcardDomain != "" {
		base := strings.TrimPrefix(h.wildcardDomain, "*.")
		if base != "" {
			fullDomain = prefix + "." + base
			isFreeDomain = true
		}
	}

	userIDStr, _ := r.Context().Value(UserIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)
	role, _ := r.Context().Value(UserRoleKey).(int16)

	// Check domain limit for User role
	if role == 2 && isFreeDomain {
		domains, err := h.tunnelUsecase.ListDomains(r.Context(), userID, role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		freeDomainCount := 0
		base := ""
		if h.wildcardDomain != "" {
			base = strings.TrimPrefix(h.wildcardDomain, "*.")
		}
		
		for _, d := range domains {
			if base != "" && strings.HasSuffix(d.Domain, "."+base) {
				freeDomainCount++
			}
		}

		maxFreeDomains := h.settingUsecase.GetMaxFreeDomains(r.Context(), h.maxFreeDomains)

		if freeDomainCount >= maxFreeDomains {
			http.Error(w, fmt.Sprintf("You have reached the maximum limit of %d free domains", maxFreeDomains), http.StatusForbidden)
			return
		}
	}

	if err := h.tunnelUsecase.AddDomain(r.Context(), fullDomain, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "domain": fullDomain})
}

// RemoveDomain removes a domain from Redis.
func (h *Handler) RemoveDomain(w http.ResponseWriter, r *http.Request) {
	if h.tunnelUsecase == nil {
		http.Error(w, "domain store not configured", http.StatusInternalServerError)
		return
	}
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}

	userIDStr, _ := r.Context().Value(UserIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)
	role, _ := r.Context().Value(UserRoleKey).(int16)

	if err := h.tunnelUsecase.RemoveDomain(r.Context(), domain, userID, role); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "message": "domain removed"})
}

// generateSubdomain menghasilkan format: app-[16_karakter_hex]
func generateSubdomain() (string, error) {
	// 8 bytes akan menghasilkan 16 karakter hexadecimal (karena 1 byte = 2 karakter hex)
	bytes := make([]byte, 8)
	
	// Mengisi byte dengan data acak yang aman secara kriptografi
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Mengubah byte acak menjadi string hexadecimal (0-9, a-f)
	randomHex := hex.EncodeToString(bytes)

	// Menggabungkan dengan prefix dan mengembalikan hasil
	return fmt.Sprintf("app-%s", randomHex), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
