package testlab

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"

	"shakerproxy.dev/shakerproxy/internal/coverage"
)

// The visibility coverage check (internal/coverage) borrows the virtual lab:
// prepare builds the namespaces and target and steers the virtual clients'
// DNS to ShakerProxy's DNS forwarder; control-api then records the virtual
// client bridge through gatewayd's normal capture path; probe sends one of
// each traffic type; cleanup removes everything. The lab never holds the
// appliance configuration lock between steps, so the capture can start.

// CoverageLease bounds how long a prepared coverage lab may live: the
// service removes it on its own if cleanup never arrives.
const CoverageLease = 4 * time.Minute

var coverageRunIDPattern = regexp.MustCompile(`^coverage-[a-f0-9]{24}$`)

func ValidCoverageRunID(id string) bool { return coverageRunIDPattern.MatchString(id) }

type CoveragePrepareRequest struct {
	RunID string `json:"run_id"`
}

type CoveragePrepareResponse struct {
	Schema    int       `json:"schema"`
	RunID     string    `json:"run_id"`
	Bridge    string    `json:"bridge"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CoverageProbeRequest struct {
	Plan coverage.Plan `json:"plan"`
}

type CoverageProbeResponse struct {
	Schema   int                     `json:"schema"`
	RunID    string                  `json:"run_id"`
	Outcomes []coverage.ProbeOutcome `json:"outcomes"`
}

type CoverageCleanupRequest struct {
	RunID string `json:"run_id"`
}

func (c Client) CoveragePrepare(ctx context.Context, runID string) (CoveragePrepareResponse, error) {
	if !ValidCoverageRunID(runID) {
		return CoveragePrepareResponse{}, errors.New("invalid coverage run ID")
	}
	var response CoveragePrepareResponse
	err := c.do(ctx, http.MethodPost, "/v1/coverage/prepare", CoveragePrepareRequest{RunID: runID}, &response)
	return response, err
}

func (c Client) CoverageProbe(ctx context.Context, plan coverage.Plan) (CoverageProbeResponse, error) {
	if !ValidCoverageRunID(plan.RunID) {
		return CoverageProbeResponse{}, errors.New("invalid coverage run ID")
	}
	var response CoverageProbeResponse
	err := c.do(ctx, http.MethodPost, "/v1/coverage/probe", CoverageProbeRequest{Plan: plan}, &response)
	return response, err
}

func (c Client) CoverageCleanup(ctx context.Context, runID string) error {
	if !ValidCoverageRunID(runID) {
		return errors.New("invalid coverage run ID")
	}
	return c.do(ctx, http.MethodPost, "/v1/coverage/cleanup", CoverageCleanupRequest{RunID: runID}, nil)
}
