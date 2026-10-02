package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/coverage"
)

// coverageCommand shows, or with `run` proves, which traffic types
// ShakerProxy sees and every way devices could bypass it.
func (c *cli) coverageCommand(args []string) error {
	if len(args) > 0 && args[0] == "run" {
		return c.coverageRunCommand(args[1:])
	}
	flags := newFlags("coverage")
	positional, err := parseFlags("coverage", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("coverage", positional, 0, 0); err != nil {
		return err
	}
	session, err := c.openAPI()
	if err != nil {
		return err
	}
	var overview coverage.Overview
	raw, err := session.getJSON("/api/v1/coverage", &overview)
	if err != nil {
		return err
	}
	if c.jsonOutput {
		return c.printRawJSON(raw)
	}
	c.printCoverage(overview)
	return nil
}

func (c *cli) coverageRunCommand(args []string) error {
	flags := newFlags("coverage run")
	passwordFile := flags.String("password-file", "", "administrator password file")
	positional, err := parseFlags("coverage", flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs("coverage", positional, 0, 0); err != nil {
		return err
	}
	if *passwordFile == "" {
		return usagef("coverage", "coverage run needs --password-file (the administrator password).")
	}
	password, err := readPasswordFile(*passwordFile)
	if err != nil {
		return err
	}
	admin, err := c.adminSession(envOr("SHAKERPROXY_API_USERNAME", "admin"), password)
	if err != nil {
		return err
	}
	defer admin.close()
	response, err := admin.do(http.MethodPost, "/api/v1/coverage/runs", map[string]any{"password": password})
	if err != nil {
		return err
	}
	var started coverage.Report
	if err := json.Unmarshal(response, &started); err != nil || started.RunID == "" {
		return errors.New("control API did not start a coverage check")
	}
	if !c.jsonOutput {
		c.println("Running the visibility coverage check: about 1 to 3 minutes while ShakerProxy records, analyzes and stores the probe traffic.")
	}
	deadline := time.Now().Add(6 * time.Minute)
	phase := ""
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		var overview coverage.Overview
		raw, err := admin.getJSON("/api/v1/coverage", &overview)
		if err != nil {
			return err
		}
		run := overview.LastRun
		if run == nil || run.RunID != started.RunID {
			continue
		}
		if run.State != coverage.StateRunning {
			if c.jsonOutput {
				return c.printRawJSON(raw)
			}
			c.printCoverage(overview)
			if run.State == coverage.StateFailed {
				return errors.New("the coverage check failed")
			}
			return nil
		}
		if !c.jsonOutput && run.Phase != phase {
			phase = run.Phase
			c.printf("  %s…\n", phase)
		}
	}
	return errors.New("the coverage check is still running; see `shakerproxy coverage` later")
}

func (c *cli) printCoverage(overview coverage.Overview) {
	run := overview.LastRun
	if run == nil {
		c.println("The visibility coverage check has not run yet. Run it with: shakerproxy coverage run --password-file FILE")
	} else {
		c.printf("Visibility coverage check (%s): %s\n", run.StartedAt.Local().Format("2006-01-02 15:04"), coverageStateWords(*run))
		if run.Error != "" {
			c.printf("  %s\n", run.Error)
		}
		if len(run.Results) > 0 {
			listing := newTable("TRAFFIC", "RESULT", "SEEN AS", "DELAY", "NOTE")
			for _, result := range run.Results {
				delay := "-"
				if result.Status == coverage.StatusPass {
					delay = fmt.Sprintf("%.1f s", float64(result.LatencyMS)/1000)
				}
				note := result.Missing
				if result.Status == coverage.StatusSkip {
					note = result.Summary
				}
				listing.add(result.Name, string(result.Status), orDash(joinLimited(result.EventKinds, 3)), delay, orDash(note))
			}
			listing.render(c.stdout, c)
		}
	}
	c.println("")
	c.printf("Ways around ShakerProxy in this lab (%d gaps):\n", overview.GapCount)
	for _, finding := range overview.Routing {
		c.printf("  [%s] %s: %s\n", finding.Status, finding.Title, finding.Detail)
		if finding.Status != coverage.FindingOK && finding.Fix != "" {
			c.printf("        Fix: %s\n", finding.Fix)
		}
	}
}

func coverageStateWords(run coverage.Report) string {
	switch run.State {
	case coverage.StateRunning:
		return "running (" + run.Phase + ")"
	case coverage.StateFailed:
		return "failed"
	default:
		return fmt.Sprintf("%d seen, %d missing or unidentified, %d not probed", run.PassCount, run.FailCount, run.SkipCount)
	}
}
