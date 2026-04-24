package handler

import (
	"embed"
	"encoding/json"
	"gotunnel/internal/webui/model"
	"gotunnel/internal/webui/service"

	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

// Handler holds shared dependencies for HTTP handlers.
type Handler struct {
	tmpl *template.Template
}

// New creates a Handler and parses embedded HTML templates.
func New(fs embed.FS) *Handler {
	tmpl := template.Must(template.ParseFS(fs,
		"templates/base.html",
		"templates/index.html",
	))
	return &Handler{tmpl: tmpl}
}

// Index renders the main config manager page.
func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	configs, err := service.ListConfigs()
	if err != nil {
		http.Error(w, "failed to list configs", http.StatusInternalServerError)
		return
	}
	if err := h.tmpl.ExecuteTemplate(w, "base", map[string]any{
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
