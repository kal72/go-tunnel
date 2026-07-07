package stats

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/stretchr/testify/assert"
)

func TestNewStatsCollector(t *testing.T) {
	sc := NewStatsCollector(5 * time.Second)
	assert.NotNil(t, sc)
	assert.Equal(t, 5*time.Second, sc.interval)
	assert.NotNil(t, sc.cpuFunc)
	assert.NotNil(t, sc.memFunc)
	assert.NotNil(t, sc.netFunc)
}

func TestStatsCollector_Collect(t *testing.T) {
	sc := NewStatsCollector(1 * time.Second)

	sc.cpuFunc = func(interval time.Duration, percpu bool) ([]float64, error) {
		return []float64{45.5}, nil
	}
	sc.memFunc = func() (*mem.VirtualMemoryStat, error) {
		return &mem.VirtualMemoryStat{
			Total:       1000,
			Used:        600,
			UsedPercent: 60.0,
		}, nil
	}
	sc.netFunc = func(pernic bool) ([]net.IOCountersStat, error) {
		return []net.IOCountersStat{
			{BytesSent: 1000, BytesRecv: 2000},
		}, nil
	}

	// First collection sets initial net counters and timestamp
	s1 := sc.Collect()
	assert.Equal(t, 45.5, s1.CPUPercent)
	assert.Equal(t, uint64(600), s1.MemUsed)
	assert.Equal(t, uint64(1000), s1.MemTotal)
	assert.Equal(t, 60.0, s1.MemPercent)
	assert.Equal(t, uint64(0), s1.NetSent)
	assert.Equal(t, uint64(0), s1.NetRecv)
	assert.Greater(t, s1.Timestamp, int64(0))

	// Simulate time passing and second collection for bandwidth delta
	time.Sleep(50 * time.Millisecond)
	sc.netFunc = func(pernic bool) ([]net.IOCountersStat, error) {
		return []net.IOCountersStat{
			{BytesSent: 1500, BytesRecv: 3000},
		}, nil
	}

	s2 := sc.Collect()
	assert.Greater(t, s2.NetSent, uint64(0))
	assert.Greater(t, s2.NetRecv, uint64(0))

	cached := sc.Get()
	assert.Equal(t, s2, cached)
}

func TestStatsCollector_Collect_Errors(t *testing.T) {
	sc := NewStatsCollector(1 * time.Second)
	sc.cpuFunc = func(interval time.Duration, percpu bool) ([]float64, error) {
		return nil, errors.New("cpu err")
	}
	sc.memFunc = func() (*mem.VirtualMemoryStat, error) {
		return nil, errors.New("mem err")
	}
	sc.netFunc = func(pernic bool) ([]net.IOCountersStat, error) {
		return nil, errors.New("net err")
	}

	s := sc.Collect()
	assert.Equal(t, 0.0, s.CPUPercent)
	assert.Equal(t, uint64(0), s.MemUsed)
	assert.Equal(t, uint64(0), s.NetSent)
}

func TestStatsCollector_Start(t *testing.T) {
	sc := NewStatsCollector(10 * time.Millisecond)
	sc.cpuFunc = func(interval time.Duration, percpu bool) ([]float64, error) {
		return []float64{10.0}, nil
	}
	sc.memFunc = nil
	sc.netFunc = nil

	sc.Start(context.Background())
	sc.Start(context.Background()) // idempotent check

	time.Sleep(30 * time.Millisecond)
	sc.Stop()
	sc.Stop() // idempotent check

	s := sc.Get()
	assert.Equal(t, 10.0, s.CPUPercent)
}
