package memory

import (
	"strings"
	"sync"
)

type HostRegistry struct {
	mu      sync.RWMutex
	allowed map[string]struct{}
	active  map[string]struct{}
}

func NewHostRegistry() *HostRegistry {
	return &HostRegistry{
		allowed: map[string]struct{}{},
		active:  map[string]struct{}{},
	}
}

// Authorize adds a host or wildcard pattern to the allowlist.
func (r *HostRegistry) Authorize(host string) {
	if host == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowed[host] = struct{}{}
}

// Deauthorize removes a host or wildcard pattern from the allowlist.
func (r *HostRegistry) Deauthorize(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.allowed, host)
}

// Register marks a host as currently used by an active tunnel.
// Returns true if successfully registered, false if already active.
func (r *HostRegistry) Register(host string) bool {
	if host == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.active[host]; exists {
		return false
	}
	r.active[host] = struct{}{}
	return true
}

// Unregister marks a host as no longer used by an active tunnel.
func (r *HostRegistry) Unregister(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.active, host)
}

// IsAuthorized checks if a host is allowed via exact match or wildcard.
func (r *HostRegistry) IsAuthorized(host string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Exact match in allowed
	if _, ok := r.allowed[host]; ok {
		return true
	}

	// Wildcard match in allowed
	// Handles one level: foo.example.com matches *.example.com
	parts := strings.SplitN(host, ".", 2)
	if len(parts) == 2 {
		wildcard := "*." + parts[1]
		if _, ok := r.allowed[wildcard]; ok {
			return true
		}
	}

	return false
}

// IsActive checks if a host is currently used by a tunnel.
func (r *HostRegistry) IsActive(host string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.active[host]
	return ok
}

// ListAllowed returns all domains in the allowlist.
func (r *HostRegistry) ListAllowed() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []string
	for host := range r.allowed {
		list = append(list, host)
	}
	return list
}
