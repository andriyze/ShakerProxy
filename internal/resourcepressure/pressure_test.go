package resourcepressure

import (
	"slices"
	"testing"
	"time"
)

func TestEvaluateCombinesCPUAndMemoryWithDiskLadder(t *testing.T) {
	now := time.Unix(100, 0)
	report := Evaluate(Evidence{CPUKnown: true, CPUStallPercent: 25, MemoryKnown: true, MemoryAvailableBytes: 10, MemoryTotalBytes: 100, DiskKnown: true, DiskAvailableBytes: 3 << 30, DiskReserveBytes: 1 << 30}, now)
	if report.Level != LevelDegraded || !report.NewCaptureAllowed || !slices.Contains(report.Causes, "CPU_PSI_DEGRADED") || !slices.Contains(report.Causes, "MEMORY_AVAILABLE_DEGRADED") {
		t.Fatalf("degraded causes lost: %#v", report)
	}
	report = Evaluate(Evidence{CPUKnown: true, CPUStallPercent: 61, MemoryKnown: true, MemoryAvailableBytes: 50, MemoryTotalBytes: 100, DiskKnown: true, DiskAvailableBytes: 1 << 30, DiskReserveBytes: 1 << 30}, now)
	if report.Level != LevelCritical || report.NewCaptureAllowed || !slices.Contains(report.Actions, "BLOCK_NEW_CAPTURES") || !slices.Contains(report.Actions, "PRESERVE_ROUTING_AND_MANAGEMENT") {
		t.Fatalf("critical degradation policy lost: %#v", report)
	}
}

func TestEvaluateNeverTreatsMissingEvidenceAsHealthy(t *testing.T) {
	report := Evaluate(Evidence{}, time.Unix(100, 0))
	if report.Level != LevelUnknown || !report.NewCaptureAllowed {
		t.Fatalf("unknown evidence was misclassified: %#v", report)
	}
}
