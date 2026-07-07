package stats

import (
	"context"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// SystemStats holds real-time system resource utilization metrics.
type SystemStats struct {
	CPUPercent float64 `json:"cpu_percent"` // CPU usage percentage 0-100
	MemUsed    uint64  `json:"mem_used"`    // Used memory in bytes
	MemTotal   uint64  `json:"mem_total"`   // Total memory in bytes
	MemPercent float64 `json:"mem_percent"` // Memory usage percentage 0-100
	NetSent    uint64  `json:"net_sent"`    // Bandwidth sent rate in bytes/sec
	NetRecv    uint64  `json:"net_recv"`    // Bandwidth recv rate in bytes/sec
	Timestamp  int64   `json:"timestamp"`   // Unix timestamp in milliseconds
}

type cpuPercentFunc func(interval time.Duration, percpu bool) ([]float64, error)
type memVirtualMemoryFunc func() (*mem.VirtualMemoryStat, error)
type netIOCountersFunc func(pernic bool) ([]net.IOCountersStat, error)

// StatsCollector periodically collects system stats in the background and caches them.
type StatsCollector struct {
	cpuFunc cpuPercentFunc
	memFunc memVirtualMemoryFunc
	netFunc netIOCountersFunc
	cancel  context.CancelFunc

	prevTime time.Time
	mu       sync.RWMutex
	cached   SystemStats
	interval time.Duration
	prevSent uint64
	prevRecv uint64
}

// NewStatsCollector initializes a new StatsCollector with a specified collection interval.
func NewStatsCollector(interval time.Duration) *StatsCollector {
	return &StatsCollector{
		interval: interval,
		cpuFunc:  cpu.Percent,
		memFunc:  mem.VirtualMemory,
		netFunc:  net.IOCounters,
	}
}

// Start runs the background stats collection loop in a goroutine until Stop or ctx is cancelled.
func (sc *StatsCollector) Start(ctx context.Context) {
	sc.mu.Lock()
	if sc.cancel != nil {
		sc.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	sc.cancel = cancel
	sc.mu.Unlock()

	sc.Collect()

	go func() {
		ticker := time.NewTicker(sc.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sc.Collect()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop terminates the background stats collection loop.
func (sc *StatsCollector) Stop() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.cancel != nil {
		sc.cancel()
		sc.cancel = nil
	}
}

// Get returns the latest cached system statistics.
func (sc *StatsCollector) Get() SystemStats {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.cached
}

// Collect gathers system statistics from OS counters and updates the cache.
func (sc *StatsCollector) Collect() SystemStats {
	var stats SystemStats
	stats.Timestamp = time.Now().UnixMilli()

	if sc.cpuFunc != nil {
		if percents, err := sc.cpuFunc(0, false); err == nil && len(percents) > 0 {
			stats.CPUPercent = percents[0]
		}
	}

	if sc.memFunc != nil {
		if vm, err := sc.memFunc(); err == nil && vm != nil {
			stats.MemUsed = vm.Used
			stats.MemTotal = vm.Total
			stats.MemPercent = vm.UsedPercent
		}
	}

	if sc.netFunc != nil {
		if counters, err := sc.netFunc(false); err == nil && len(counters) > 0 {
			now := time.Now()
			currentSent := counters[0].BytesSent
			currentRecv := counters[0].BytesRecv

			sc.mu.Lock()
			if !sc.prevTime.IsZero() && now.After(sc.prevTime) {
				elapsed := now.Sub(sc.prevTime).Seconds()
				if elapsed > 0 {
					if currentSent >= sc.prevSent {
						stats.NetSent = uint64(float64(currentSent-sc.prevSent) / elapsed)
					}
					if currentRecv >= sc.prevRecv {
						stats.NetRecv = uint64(float64(currentRecv-sc.prevRecv) / elapsed)
					}
				}
			}
			sc.prevSent = currentSent
			sc.prevRecv = currentRecv
			sc.prevTime = now
			sc.mu.Unlock()
		}
	}

	sc.mu.Lock()
	sc.cached = stats
	sc.mu.Unlock()

	return stats
}
