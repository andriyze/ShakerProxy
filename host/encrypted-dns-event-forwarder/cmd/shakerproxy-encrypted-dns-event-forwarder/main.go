package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/cloudconnector"
)

const version = "0.1.0-dev.1"

var prefixes = map[string]struct {
	Transport string
	Reason    string
}{
	"SHAKERPROXY_EDNS_DOT":     {Transport: "dot", Reason: "blocked_dot_port_853"},
	"SHAKERPROXY_EDNS_DOQ":     {Transport: "doq", Reason: "blocked_doq_port_853"},
	"SHAKERPROXY_EDNS_DOH_TCP": {Transport: "doh", Reason: "blocked_known_doh_endpoint"},
	"SHAKERPROXY_EDNS_DOH_UDP": {Transport: "doh3", Reason: "blocked_known_doh3_endpoint"},
	"SHAKERPROXY_EDNS_QUIC":    {Transport: "unknown", Reason: "strict_policy_blocked_all_quic"},
}

type metadataSink interface {
	Enqueue(context.Context, []cloudconnector.LocalMetadataEvent) error
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: shakerproxy-encrypted-dns-event-forwarder [version]")
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	socket := envOr("SHAKERPROXY_CLOUD_CONNECTOR_SOCKET", "/run/shakerproxy-cloud/connector.sock")
	journalctl := envOr("SHAKERPROXY_JOURNALCTL_BINARY", "/usr/bin/journalctl")
	client, err := cloudconnector.NewLocalMetadataClient(socket, 10*time.Second)
	if err != nil {
		logger.Error("encrypted DNS metadata connector rejected", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger, client, journalctl); err != nil && ctx.Err() == nil {
		logger.Error("encrypted DNS event forwarder stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, sink metadataSink, journalctl string) error {
	command := exec.CommandContext(ctx, journalctl, "--dmesg", "--follow", "--output=cat", "--since=now", "--no-pager")
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 256<<10)
	batch := make([]cloudconnector.LocalMetadataEvent, 0, 32)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := sink.Enqueue(ctx, batch); err != nil {
			logger.Warn("encrypted DNS metadata enqueue failed", "error", err)
		} else {
			batch = batch[:0]
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lineChannel := make(chan string, 32)
	errorChannel := make(chan error, 1)
	go func() {
		for scanner.Scan() {
			select {
			case lineChannel <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
		errorChannel <- scanner.Err()
	}()
	for {
		select {
		case <-ctx.Done():
			flush()
			_ = command.Wait()
			return nil
		case err := <-errorChannel:
			flush()
			if err != nil {
				return err
			}
			return command.Wait()
		case <-ticker.C:
			flush()
		case line := <-lineChannel:
			event, ok := parseLine(line, time.Now().UTC())
			if !ok {
				continue
			}
			if len(batch) >= 256 {
				copy(batch, batch[len(batch)-255:])
				batch = batch[:255]
				logger.Warn("encrypted DNS metadata buffer full; oldest event dropped")
			}
			batch = append(batch, event)
			if len(batch) >= 32 {
				flush()
			}
		}
	}
}

func parseLine(line string, observedAt time.Time) (cloudconnector.LocalMetadataEvent, bool) {
	fields := strings.Fields(line)
	var classification struct {
		Transport string
		Reason    string
	}
	matched := false
	values := make(map[string]string)
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if value, ok := prefixes[strings.TrimSuffix(field, ":")]; ok {
			classification = value
			matched = true
			continue
		}
		if index := strings.IndexByte(field, '='); index > 0 && index < len(field)-1 {
			values[strings.ToUpper(field[:index])] = strings.Trim(field[index+1:], "\"")
		}
	}
	if !matched {
		return cloudconnector.LocalMetadataEvent{}, false
	}
	sourceIP := net.ParseIP(values["SRC"])
	destinationIP := net.ParseIP(values["DST"])
	if sourceIP == nil || destinationIP == nil {
		return cloudconnector.LocalMetadataEvent{}, false
	}
	attributes := map[string]any{
		"source":    "nftables-kernel-log",
		"source_ip": sourceIP.String(),
		"protocol":  strings.ToLower(values["PROTO"]),
	}
	if value, err := strconv.Atoi(values["SPT"]); err == nil && value >= 0 && value <= 65535 {
		attributes["source_port"] = value
	}
	if value, err := strconv.Atoi(values["DPT"]); err == nil && value >= 0 && value <= 65535 {
		attributes["destination_port"] = value
	}
	payload := map[string]any{
		"client_ip":            sourceIP.String(),
		"resolver_ip":          destinationIP.String(),
		"query_name":           "encrypted-query",
		"query_type":           "",
		"transport":            classification.Transport,
		"encrypted":            true,
		"resolver_provider":    "",
		"detection_confidence": 0.99,
		"blocked":              true,
		"policy_reason":        classification.Reason,
		"attributes":           attributes,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return cloudconnector.LocalMetadataEvent{}, false
	}
	return cloudconnector.LocalMetadataEvent{
		Type:       cloudconnector.MetadataDNSEvent,
		ObservedAt: observedAt.UTC(),
		Payload:    encoded,
	}, true
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
