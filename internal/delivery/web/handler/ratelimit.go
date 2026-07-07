package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// RateLimitPage renders the standalone Rate Limiting & Traffic Protection page.
func (h *Handler) RateLimitPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Rate Limiting - Tunnel Manager",
	}

	role, _ := r.Context().Value(UserRoleKey).(int16)
	username, _ := r.Context().Value(UserNameKey).(string)
	csrf, _ := r.Context().Value(CSRFTokenKey).(string)

	data["UserRole"] = role
	data["UserName"] = username
	data["CSRFToken"] = csrf
	data["DomainEnabled"] = true

	err := h.ratelimitTmpl.ExecuteTemplate(w, "base", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// GetRateLimit returns rate limiting config. For regular users, considers per-user enabled toggle.
func (h *Handler) GetRateLimit(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(UserRoleKey).(int16)
	username, _ := r.Context().Value(UserNameKey).(string)

	settings, err := h.settingUsecase.GetAllSettings(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	enabled := true
	if val, ok := settings["rate_limit_enabled"]; ok {
		enabled = val != "false"
	}
	if role != 1 && username != "" {
		if val, ok := settings["rate_limit_enabled:"+username]; ok && val != "" {
			enabled = val == "true"
		} else {
			enabled = false
		}
	}

	rate := "100"
	if val, ok := settings["rate_limit_rate"]; ok && val != "" {
		rate = val
	}

	burst := "20"
	if val, ok := settings["rate_limit_burst"]; ok && val != "" {
		burst = val
	}

	adminAllowed := false
	if val, ok := settings["rate_limit_admin_allowed"]; ok {
		adminAllowed = val == "true"
	}

	writeJSON(w, map[string]interface{}{
		"status": "ok",
		"config": map[string]interface{}{
			"enabled":       enabled,
			"rate":          rate,
			"burst":         burst,
			"admin_allowed": adminAllowed,
		},
	})
}

type updateRateLimitRequest struct {
	Config struct {
		Rate         interface{} `json:"rate"`
		Burst        interface{} `json:"burst"`
		Enabled      bool        `json:"enabled"`
		AdminAllowed bool        `json:"admin_allowed"`
	} `json:"config"`
}

// UpdateRateLimit updates rate limiting settings. Regular users can only toggle active/inactive status.
func (h *Handler) UpdateRateLimit(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(UserRoleKey).(int16)
	username, _ := r.Context().Value(UserNameKey).(string)

	var req updateRateLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if role != 1 {
		if username == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Regular user can ONLY update their own toggle
		if err := h.settingUsecase.SetSetting(ctx, "rate_limit_enabled:"+username, strconv.FormatBool(req.Config.Enabled)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if h.tunnelUsecase != nil {
			_ = h.tunnelUsecase.SetRateLimitSetting(ctx, username, strconv.FormatBool(req.Config.Enabled))
		}
		writeJSON(w, map[string]interface{}{"status": "ok"})
		return
	}

	// Admin updates global settings
	if err := h.settingUsecase.SetSetting(ctx, "rate_limit_enabled", strconv.FormatBool(req.Config.Enabled)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rateStr := fmtVal(req.Config.Rate, "100")
	if err := h.settingUsecase.SetSetting(ctx, "rate_limit_rate", rateStr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	burstStr := fmtVal(req.Config.Burst, "20")
	if err := h.settingUsecase.SetSetting(ctx, "rate_limit_burst", burstStr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.settingUsecase.SetSetting(ctx, "rate_limit_admin_allowed", strconv.FormatBool(req.Config.AdminAllowed)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{"status": "ok"})
}

func fmtVal(val interface{}, def string) string {
	if val == nil {
		return def
	}
	switch v := val.(type) {
	case string:
		if v == "" {
			return def
		}
		return v
	case float64:
		return strconv.Itoa(int(v))
	case int:
		return strconv.Itoa(v)
	default:
		return def
	}
}
