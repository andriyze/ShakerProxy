package resourcepressure

import "time"

type Level string

const (
	LevelNormal   Level = "NORMAL"
	LevelDegraded Level = "DEGRADED"
	LevelCritical Level = "CRITICAL"
	LevelUnknown  Level = "UNKNOWN"
)

type Evidence struct {
	CPUStallPercent      float64
	CPUKnown             bool
	MemoryAvailableBytes uint64
	MemoryTotalBytes     uint64
	MemoryKnown          bool
	DiskAvailableBytes   uint64
	DiskReserveBytes     uint64
	DiskKnown            bool
}

type Report struct {
	Schema                 int       `json:"schema"`
	GeneratedAt            time.Time `json:"generated_at"`
	Level                  Level     `json:"level"`
	CPUStallPercent        float64   `json:"cpu_stall_percent,omitempty"`
	MemoryAvailablePercent float64   `json:"memory_available_percent,omitempty"`
	DiskAvailableBytes     uint64    `json:"disk_available_bytes,omitempty"`
	Causes                 []string  `json:"causes"`
	Actions                []string  `json:"actions"`
	NewCaptureAllowed      bool      `json:"new_capture_allowed"`
}

func Evaluate(e Evidence, now time.Time) Report {
	report := Report{Schema: 1, GeneratedAt: now.UTC(), Level: LevelNormal, Causes: []string{}, Actions: []string{}, NewCaptureAllowed: true}
	known := e.CPUKnown || e.MemoryKnown || e.DiskKnown
	critical, degraded := false, false
	if e.CPUKnown {
		report.CPUStallPercent = e.CPUStallPercent
		if e.CPUStallPercent >= 60 {
			critical = true
			report.Causes = append(report.Causes, "CPU_PSI_CRITICAL")
		} else if e.CPUStallPercent >= 20 {
			degraded = true
			report.Causes = append(report.Causes, "CPU_PSI_DEGRADED")
		}
	}
	if e.MemoryKnown && e.MemoryTotalBytes > 0 {
		report.MemoryAvailablePercent = float64(e.MemoryAvailableBytes) * 100 / float64(e.MemoryTotalBytes)
		if report.MemoryAvailablePercent <= 5 {
			critical = true
			report.Causes = append(report.Causes, "MEMORY_AVAILABLE_CRITICAL")
		} else if report.MemoryAvailablePercent <= 15 {
			degraded = true
			report.Causes = append(report.Causes, "MEMORY_AVAILABLE_DEGRADED")
		}
	}
	if e.DiskKnown {
		report.DiskAvailableBytes = e.DiskAvailableBytes
		if e.DiskAvailableBytes <= e.DiskReserveBytes {
			critical = true
			report.Causes = append(report.Causes, "DISK_RESERVE_CRITICAL")
		} else if e.DiskAvailableBytes <= 2*e.DiskReserveBytes {
			degraded = true
			report.Causes = append(report.Causes, "DISK_RESERVE_DEGRADED")
		}
	}
	switch {
	case !known:
		report.Level = LevelUnknown
		report.Actions = []string{"PRESERVE_ROUTING_AND_MANAGEMENT", "REPORT_UNKNOWN_EVIDENCE"}
	case critical:
		report.Level = LevelCritical
		report.NewCaptureAllowed = false
		report.Actions = []string{"BLOCK_NEW_CAPTURES", "REDUCE_LIVE_REFRESH", "PRESERVE_ROUTING_AND_MANAGEMENT"}
	case degraded:
		report.Level = LevelDegraded
		report.Actions = []string{"REDUCE_LIVE_REFRESH", "PRESERVE_ROUTING_AND_MANAGEMENT"}
	default:
		report.Actions = []string{"PRESERVE_ROUTING_AND_MANAGEMENT"}
	}
	return report
}
