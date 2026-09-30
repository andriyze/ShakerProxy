package cloudconnector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

type LocalConnectorStatus struct {
	Enrolled        bool   `json:"enrolled"`
	SensorID        string `json:"sensor_id,omitempty"`
	OrganizationID  string `json:"organization_id,omitempty"`
	ProtocolVersion string `json:"protocol_version"`
}

type LocalMetadataClient struct {
	SocketPath string
	Client     *http.Client
}

func NewLocalMetadataClient(socketPath string, timeout time.Duration) (*LocalMetadataClient, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || !filepath.IsAbs(socketPath) || strings.ContainsRune(socketPath, '\x00') {
		return nil, errors.New("cloud connector socket path must be absolute")
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("cloud connector timeout must be between one second and one minute")
	}
	transport := &http.Transport{
		DisableCompression: true,
		Proxy:              nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &LocalMetadataClient{SocketPath: socketPath, Client: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

func (client *LocalMetadataClient) Status(ctx context.Context) (LocalConnectorStatus, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/status", nil)
	if err != nil {
		return LocalConnectorStatus{}, err
	}
	response, err := client.httpClient().Do(request)
	if err != nil {
		return LocalConnectorStatus{}, fmt.Errorf("read local cloud connector status: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
		return LocalConnectorStatus{}, fmt.Errorf("local cloud connector status returned HTTP %d", response.StatusCode)
	}
	var status LocalConnectorStatus
	if err := decodeBoundedClientJSON(response.Body, 32<<10, &status); err != nil {
		return LocalConnectorStatus{}, fmt.Errorf("decode local cloud connector status: %w", err)
	}
	if status.ProtocolVersion != ProtocolVersion {
		return LocalConnectorStatus{}, errors.New("local cloud connector protocol version is unsupported")
	}
	if status.Enrolled && (strings.TrimSpace(status.SensorID) == "" || strings.TrimSpace(status.OrganizationID) == "") {
		return LocalConnectorStatus{}, errors.New("local cloud connector enrollment identity is incomplete")
	}
	return status, nil
}

func (client *LocalMetadataClient) Enqueue(ctx context.Context, events []LocalMetadataEvent) error {
	if len(events) == 0 || len(events) > MaxMetadataEnqueueEvents {
		return errors.New("local metadata batch must contain between 1 and 500 events")
	}
	encoded, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return err
	}
	if len(encoded) > MaxMetadataRequestBytes {
		return errors.New("local metadata request exceeds 2 MiB")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/metadata/enqueue", bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient().Do(request)
	if err != nil {
		return fmt.Errorf("queue local cloud metadata: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("local cloud metadata queue returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (client *LocalMetadataClient) httpClient() *http.Client {
	if client != nil && client.Client != nil {
		return client.Client
	}
	return http.DefaultClient
}

func decodeBoundedClientJSON(reader io.Reader, maximum int64, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, maximum+1))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("response contains trailing JSON")
	}
	return nil
}
