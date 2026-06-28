package handler

import (
	"net/http"

	"gotunnel/internal/delivery/web/dto"
	usecaseConfig "gotunnel/internal/usecase/config"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// CLIHandler serves API endpoints consumed by the gotunnel CLI client.
type CLIHandler struct {
	configUsecase usecaseConfig.ConfigUsecase
	tunnelAddr    string
	latestVersion string
	acmeEnable    bool
}

// NewCLIHandler creates a new CLIHandler.
func NewCLIHandler(configUsecase usecaseConfig.ConfigUsecase, tunnelAddr string, acmeEnable bool, latestVersion string) *CLIHandler {
	return &CLIHandler{
		configUsecase: configUsecase,
		tunnelAddr:    tunnelAddr,
		acmeEnable:    acmeEnable,
		latestVersion: latestVersion,
	}
}

// ClientGetConfigs returns a list of config names for the CLI.
func (h *CLIHandler) ClientGetConfigs(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(UserIDKey).(string)
	uid, _ := uuid.Parse(userID)

	configs, err := h.configUsecase.GetConfigsByUserID(r.Context(), uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	names := make([]map[string]string, 0, len(configs))
	for _, c := range configs {
		names = append(names, map[string]string{"name": c.Name})
	}

	writeJSON(w, names)
}

// ClientGetConfig returns the ClientConfig payload for the CLI.
func (h *CLIHandler) ClientGetConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	userID, _ := r.Context().Value(UserIDKey).(string)
	uid, _ := uuid.Parse(userID)

	cfg, err := h.configUsecase.GetConfigByName(r.Context(), uid, name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cfg == nil {
		http.Error(w, "config not found", http.StatusNotFound)
		return
	}

	clientConfig := dto.ClientConfigDTO{
		TunnelAddr:    h.tunnelAddr,
		SkipTLSVerify: !h.acmeEnable,
		ClientID:      cfg.ID.String(),
		ClientName:    cfg.Name,
		AuthToken:     "", // Client uses its own JWT.
		Tunnels:       cfg.Tunnels,
	}

	writeJSON(w, clientConfig)
}

// ClientGetVersion returns the latest version info for the CLI.
func (h *CLIHandler) ClientGetVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{
		"version":      h.latestVersion,
		"download_url": "/dl/gotunnel-{os}-{arch}",
	})
}
