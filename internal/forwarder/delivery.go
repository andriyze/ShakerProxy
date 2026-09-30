package forwarder

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	if interval < 100*time.Millisecond {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		_ = m.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) RunOnce(ctx context.Context) error {
	m.mu.Lock()
	storeLock, err := m.lockStore()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	doc, err := m.loadConfiguration(true)
	unlockStore(storeLock)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	integrations := append([]Integration(nil), doc.Integrations...)
	m.mu.Unlock()
	var firstError error
	for _, integration := range integrations {
		if !integration.Enabled {
			continue
		}
		for count := 0; count < 64; count++ {
			delivered, err := m.deliverFirst(ctx, integration)
			if err != nil {
				if firstError == nil {
					firstError = err
				}
				break
			}
			if !delivered {
				break
			}
		}
	}
	return firstError
}

func (m *Manager) deliverFirst(ctx context.Context, integration Integration) (bool, error) {
	m.mu.Lock()
	storeLock, err := m.lockStore()
	if err != nil {
		m.mu.Unlock()
		return false, err
	}
	state, err := m.loadState(integration.ID)
	if err != nil || len(state.Pending) == 0 || state.Pending[0].NextAttemptAt.After(m.now()) {
		unlockStore(storeLock)
		m.mu.Unlock()
		return false, err
	}
	delivery := state.Pending[0]
	unlockStore(storeLock)
	m.mu.Unlock()

	encoded, err := json.Marshal(delivery.Event)
	if err == nil {
		switch integration.Kind {
		case KindJSONL:
			err = m.deliverJSONL(integration, encoded)
		case KindWebhook:
			err = deliverWebhook(ctx, integration, delivery.Event.Sequence, encoded)
		case KindSyslogTLS:
			err = deliverSyslogTLS(ctx, integration, delivery.Event, encoded)
		default:
			err = errors.New("unsupported forwarder transport")
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	storeLock, lockErr := m.lockStore()
	if lockErr != nil {
		return false, lockErr
	}
	defer unlockStore(storeLock)
	state, loadErr := m.loadState(integration.ID)
	if loadErr != nil {
		return false, loadErr
	}
	if len(state.Pending) == 0 || state.Pending[0].Event.Sequence != delivery.Event.Sequence || state.Pending[0].Digest != delivery.Digest {
		return false, errors.New("forwarder queue head changed during delivery")
	}
	now := m.now()
	if err == nil {
		state.Pending = append([]Delivery(nil), state.Pending[1:]...)
		state.Delivered++
		state.LastSuccessAt = &now
		state.LastError = ""
	} else {
		state.Pending[0].Attempts++
		backoff := time.Second << min(state.Pending[0].Attempts-1, 8)
		state.Pending[0].NextAttemptAt = now.Add(backoff)
		state.LastFailureAt = &now
		state.LastError = boundedError(err)
	}
	if saveErr := m.saveState(state); saveErr != nil {
		return false, saveErr
	}
	return err == nil, err
}

func (m *Manager) deliverJSONL(integration Integration, encoded []byte) error {
	directory := filepath.Join(m.Root, "output")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	path := filepath.Join(directory, integration.ID+".jsonl")
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size()+int64(len(encoded))+1 > MaxJSONLBytes {
		return errors.New("bounded JSONL destination is full or unsafe")
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func deliverWebhook(ctx context.Context, integration Integration, sequence uint64, encoded []byte) error {
	target, err := url.Parse(integration.Destination)
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: target.Hostname()}, DialContext: safeDialContext(target.Hostname()), ResponseHeaderTimeout: 5 * time.Second, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(string(encoded)))
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, []byte(integration.HMACSecret))
	_, _ = mac.Write([]byte(strconv.FormatUint(sequence, 10)))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write(encoded)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "ShakerProxy-Forwarder/1")
	request.Header.Set("X-ShakerProxy-Sequence", strconv.FormatUint(sequence, 10))
	request.Header.Set("X-ShakerProxy-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}

func deliverSyslogTLS(ctx context.Context, integration Integration, event SafeEvent, encoded []byte) error {
	target, err := url.Parse(integration.Destination)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	addresses, err := safeResolve(ctx, target.Hostname())
	if err != nil {
		return err
	}
	var connection net.Conn
	for _, address := range addresses {
		connection, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(address.String(), "6514"), &tls.Config{MinVersion: tls.VersionTLS13, ServerName: target.Hostname()})
		if err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	} else {
		_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	}
	message := fmt.Sprintf("<134>1 %s %s shakerproxy - %s - %s\n", event.OccurredAt.Format(time.RFC3339Nano), event.ApplianceID, event.EventID, encoded)
	_, err = io.WriteString(connection, message)
	return err
}

func safeDialContext(expectedHost string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(host, expectedHost) || port != "443" {
			return nil, errors.New("webhook dial target changed")
		}
		addresses, err := safeResolve(ctx, host)
		if err != nil {
			return nil, err
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
		var last error
		for _, resolved := range addresses {
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
			if err == nil {
				return connection, nil
			}
			last = err
		}
		return nil, last
	}
}

func safeResolve(ctx context.Context, host string) ([]net.IP, error) {
	if direct := net.ParseIP(host); direct != nil {
		if !safeExternalIP(direct) {
			return nil, errors.New("forwarder destination resolves to a non-public address")
		}
		return []net.IP{direct}, nil
	}
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("forwarder destination could not be resolved")
	}
	for _, address := range addresses {
		if !safeExternalIP(address) {
			return nil, errors.New("forwarder destination includes a non-public address")
		}
	}
	return addresses, nil
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.Map(func(char rune) rune {
		if char < 0x20 || char == 0x7f {
			return ' '
		}
		return char
	}, err.Error())
	if len(message) > 256 {
		message = message[:256]
	}
	return message
}
