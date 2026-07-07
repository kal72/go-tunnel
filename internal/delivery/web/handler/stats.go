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
	type prerendered struct {
		CPU     string
		Mem     string
		MemUsed string
		NetSent string
		NetRecv string
	}
	pre := prerendered{"0.0%", "0.0%", "0 B / 0 B", "0 B/s", "0 B/s"}

	var initialStats interface{} = map[string]interface{}{
		"cpu_percent": 0.0,
		"mem_used":    0,
		"mem_total":   0,
		"mem_percent": 0.0,
		"net_sent":    0,
		"net_recv":    0,
	}
	if h.statsCollector != nil {
		s := h.statsCollector.Get()
		initialStats = s
		pre.CPU = fmt.Sprintf("%.1f%%", s.CPUPercent)
		pre.Mem = fmt.Sprintf("%.1f%%", s.MemPercent)
		pre.MemUsed = fmtBytes(s.MemUsed) + " / " + fmtBytes(s.MemTotal)
		pre.NetSent = fmtBytes(s.NetSent) + "/s"
		pre.NetRecv = fmtBytes(s.NetRecv) + "/s"
	}

	initialJSON, err := json.Marshal(initialStats)
	if err != nil {
		initialJSON = []byte("{}")
	}

	data := map[string]interface{}{
		"Title":         "System Statistics - Tunnel Manager",
		"UserRole":      role,
		"UserName":      username,
		"CSRFToken":     csrf,
		"DomainEnabled": true,
		"InitialStats":  string(initialJSON),
		"Pre":           pre,
	}

	if err := h.statsTmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// fmtBytes formats a byte count to a human-readable string,
// matching the JavaScript formatBytes() function used in the stats template.
func fmtBytes(b uint64) string {
	if b == 0 {
		return "0 B"
	}
	const k = 1024.0
	units := [5]string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	v := float64(b)
	for v >= k && i < len(units)-1 {
		v /= k
		i++
	}
	// Format with up to 2 decimal places, stripping trailing zeros (mirrors JS parseFloat(x.toFixed(2)))
	s := fmt.Sprintf("%.2f", v)
	for len(s) > 1 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s + " " + units[i]
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
