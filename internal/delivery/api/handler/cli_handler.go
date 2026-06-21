package api

import (
	"encoding/json"
	"net/http"

	"gotunnel/internal/domain/config"
	usecaseConfig "gotunnel/internal/usecase/config"

	webhandler "gotunnel/internal/delivery/web/handler"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type CLIHandler struct {
	configUsecase usecaseConfig.ConfigUsecase
	tunnelAddr    string
	acmeEnable    bool
}

func NewCLIHandler(configUsecase usecaseConfig.ConfigUsecase, tunnelAddr string, acmeEnable bool) *CLIHandler {
	return &CLIHandler{
		configUsecase: configUsecase,
		tunnelAddr:    tunnelAddr,
		acmeEnable:    acmeEnable,
	}
}

// ClientGetConfigs returns a list of config names for the CLI.
func (h *CLIHandler) ClientGetConfigs(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(webhandler.UserIDKey).(string)
	uid, _ := uuid.Parse(userID)

	configs, err := h.configUsecase.GetConfigsByUserID(r.Context(), uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	names := make([]map[string]string, 0)
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

	userID, _ := r.Context().Value(webhandler.UserIDKey).(string)
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

	clientConfig := config.ClientAppConfig{
		TunnelAddr:    h.tunnelAddr,
		SkipTLSVerify: !h.acmeEnable,
		ClientID:      cfg.ID.String(),
		ClientName:    cfg.Name,
		AuthToken:     "", // Client uses its own JWT
		Tunnels:       cfg.Tunnels,
	}

	writeJSON(w, clientConfig)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
