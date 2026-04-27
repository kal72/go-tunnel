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
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

type Handler struct {
	dashTmpl     *template.Template
	confTmpl     *template.Template
	store        state.Store
	masterSecret string
}

// New creates a Handler and parses embedded HTML templates.
func New(fs embed.FS, store state.Store, masterSecret string) *Handler {
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

	return &Handler{
		dashTmpl:     dashTmpl,
		confTmpl:     confTmpl,
		store:        store,
		masterSecret: masterSecret,
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
					"Client":      info.Client,
					"Hosts":       strings.Join(info.Hosts, ", "),
					"ConnectedAt": info.ConnectedAt.Format(time.RFC3339),
					"LastPing":    info.LastPing.Format("15:04:05"),
				})
			}
		}
	}

	if err := h.dashTmpl.ExecuteTemplate(w, "base", map[string]any{
		"Tunnels": tunnels,
	}); err != nil {
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
		"Configs": configs,
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
func (h *Handler) GenerateToken(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		http.Error(w, "client_id required", http.StatusBadRequest)
		return
	}

	mac := hmac.New(sha256.New, []byte(h.masterSecret))
	mac.Write([]byte(clientID))
	token := fmt.Sprintf("%x", mac.Sum(nil))

	writeJSON(w, map[string]string{"token": token})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
