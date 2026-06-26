package handler

import (
	"encoding/json"
	"net/http"
)

// Settings Page.
func (h *Handler) SettingsPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "System Settings - Tunnel Manager",
	}

	role, _ := r.Context().Value(UserRoleKey).(int16)
	username, _ := r.Context().Value(UserNameKey).(string)
	csrf, _ := r.Context().Value(CSRFTokenKey).(string)

	data["UserRole"] = role
	data["UserName"] = username
	data["CSRFToken"] = csrf
	data["DomainEnabled"] = h.wildcardDomain != ""

	err := h.settingTmpl.ExecuteTemplate(w, "base", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// GetSettings API.
func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.settingUsecase.GetAllSettings(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Supply defaults if not exist
	if _, ok := settings["max_free_domains"]; !ok {
		settings["max_free_domains"] = "5" // could also format h.maxFreeDomains
	}
	if _, ok := settings["allow_registration"]; !ok {
		settings["allow_registration"] = "true"
	}
	if _, ok := settings["max_tunnels_per_user"]; !ok {
		settings["max_tunnels_per_user"] = "3"
	}

	writeJSON(w, map[string]interface{}{
		"status":   "ok",
		"settings": settings,
	})
}

// UpdateSettings API.
func (h *Handler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Settings map[string]string `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	for k, v := range payload.Settings {
		if err := h.settingUsecase.SetSetting(r.Context(), k, v); err != nil {
			http.Error(w, "failed to save setting "+k, http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, map[string]string{
		"status":  "ok",
		"message": "Settings updated successfully",
	})
}
