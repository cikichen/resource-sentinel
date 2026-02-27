package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type Collector interface {
	Collect(ctx context.Context) (Sample, error)
}

type SystemCollector struct {
	diskPath        string
	cpuSampleWindow time.Duration
}

func NewSystemCollector(diskPath string, cpuSampleWindow time.Duration) *SystemCollector {
	if diskPath == "" {
		diskPath = "/"
	}
	if cpuSampleWindow <= 0 {
		cpuSampleWindow = time.Second
	}

	return &SystemCollector{
		diskPath:        diskPath,
		cpuSampleWindow: cpuSampleWindow,
	}
}

func (c *SystemCollector) Collect(ctx context.Context) (Sample, error) {
	cpuValues, err := cpu.PercentWithContext(ctx, c.cpuSampleWindow, false)
	if err != nil {
		return Sample{}, fmt.Errorf("collect cpu usage: %w", err)
	}
	if len(cpuValues) == 0 {
		return Sample{}, fmt.Errorf("collect cpu usage: no data")
	}

	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return Sample{}, fmt.Errorf("collect memory usage: %w", err)
	}

	diskUsage, err := disk.UsageWithContext(ctx, c.diskPath)
	if err != nil {
		return Sample{}, fmt.Errorf("collect disk usage: %w", err)
	}

	return Sample{
		CPU:    cpuValues[0],
		Memory: vm.UsedPercent,
		Disk:   diskUsage.UsedPercent,
		At:     time.Now(),
	}, nil
}
