package server

import (
	"context"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
)

type analyzerStatusEntry struct {
	Engine    analyzer.Engine          `json:"engine"`
	Available bool                     `json:"available"`
	Health    *analyzer.HealthSnapshot `json:"health,omitempty"`
	Failure   string                   `json:"failure,omitempty"`
}

type analyzerStatusReport struct {
	Schema      int                   `json:"schema"`
	GeneratedAt time.Time             `json:"generated_at"`
	Analyzers   []analyzerStatusEntry `json:"analyzers"`
}

func (s *Server) analyzerStatus(w http.ResponseWriter, r *http.Request) {
	type request struct {
		engine analyzer.Engine
		client analyzerStatusService
	}
	requests := []request{{engine: analyzer.EngineZeek, client: s.zeekAnalyzerStatus}, {engine: analyzer.EngineSuricata, client: s.suricataAnalyzerStatus}}
	report := analyzerStatusReport{Schema: 1, GeneratedAt: time.Now().UTC(), Analyzers: make([]analyzerStatusEntry, 0, len(requests))}
	for _, item := range requests {
		entry := analyzerStatusEntry{Engine: item.engine}
		if item.client == nil {
			entry.Failure = "Analyzer status is not configured"
			report.Analyzers = append(report.Analyzers, entry)
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		health, err := item.client.Status(ctx)
		cancel()
		if err != nil || health.Validate() != nil || health.Engine != item.engine {
			entry.Failure = "Analyzer status is temporarily unavailable"
		} else {
			entry.Available = true
			entry.Health = &health
		}
		report.Analyzers = append(report.Analyzers, entry)
	}
	writeJSON(w, http.StatusOK, report)
}
