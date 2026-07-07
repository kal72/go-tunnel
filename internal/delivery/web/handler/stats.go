package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// StatsPage renders the System Statistics dashboard page (Admin only).
func (h *Handler) StatsPage(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(UserRoleKey).(int16)
	username, _ := r.Context().Value(UserNameKey).(string)
	csrf, _ := r.Context().Value(CSRFTokenKey).(string)

	// Inject current stats so Alpine.js initializes with real values,
	// eliminating the 0 → real-value flash that causes layout shift.
	var initialStats interface{} = map[string]interface{}{
		"cpu_percent": 0.0,
		"mem_used":    0,
		"mem_total":   0,
		"mem_percent": 0.0,
		"net_sent":    0,
		"net_recv":    0,
	}
	if h.statsCollector != nil {
		initialStats = h.statsCollector.Get()
	}

	initialJSON, err := json.Marshal(initialStats)
	if err != nil {
		initialJSON = []byte("{}")
	}

	data := map[string]interface{}{
		"Title":        "System Statistics - Tunnel Manager",
		"UserRole":     role,
		"UserName":     username,
		"CSRFToken":    csrf,
		"DomainEnabled": true,
		"InitialStats": string(initialJSON),
	}

	if err := h.statsTmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// StreamStats streams real-time system stats updates via Server-Sent Events (SSE) every 5 seconds.
func (h *Handler) StreamStats(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sendStats := func() bool {
		var statsObj interface{}
		if h.statsCollector != nil {
			statsObj = h.statsCollector.Get()
		} else {
			statsObj = map[string]interface{}{"error": "stats collector not initialized"}
		}

		data, err := json.Marshal(statsObj)
		if err != nil {
			return true
		}

		_, err = fmt.Fprintf(w, "data: %s\n\n", data)
		if err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !sendStats() {
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !sendStats() {
				return
			}
		}
	}
}
