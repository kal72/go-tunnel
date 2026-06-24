package registry

import "sync"

type HostRegistry struct {
	mu    sync.RWMutex
	hosts map[string]struct{}
}

func NewHostRegistry() *HostRegistry {
	return &HostRegistry{hosts: map[string]struct{}{}}
}

func (r *HostRegistry) Add(host string) bool {
	if host == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.hosts[host]; exists {
		return false
	}
	r.hosts[host] = struct{}{}
	return true
}

func (r *HostRegistry) Remove(host string) {
	if host == "" {
		return
	}
	r.mu.Lock()
	delete(r.hosts, host)
	r.mu.Unlock()
}

func (r *HostRegistry) Exists(host string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.hosts[host]
	return ok
}
