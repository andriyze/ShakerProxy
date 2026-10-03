package notify

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
	"strings"
	"time"
)

// WebhookBody is the generic JSON a WEBHOOK channel receives. It is
// payload-free: it carries what happened and the subject, never a secret.
type WebhookBody struct {
	Schema    int       `json:"schema"`
	Type      string    `json:"type"`
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Trigger   Trigger   `json:"trigger"`
	Severity  Severity  `json:"severity"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Subject   Subject   `json:"subject"`
}

// WebhookSchema versions the outbound body.
const WebhookSchema = 1

// RenderWebhook builds the generic webhook body.
func RenderWebhook(n Notification) WebhookBody {
	return WebhookBody{
		Schema:    WebhookSchema,
		Type:      "shakerproxy.notification",
		ID:        n.ID,
		CreatedAt: n.CreatedAt.UTC(),
		Trigger:   n.Trigger,
		Severity:  n.Severity,
		Title:     n.Title,
		Body:      n.Body,
		Subject:   n.Subject,
	}
}

// RenderSlack builds a Slack-compatible incoming-webhook body, which Slack,
// Mattermost and Discord-compatible endpoints accept.
func RenderSlack(n Notification) map[string]any {
	emoji := map[Severity]string{SeverityCritical: ":rotating_light:", SeverityWarning: ":warning:", SeverityInfo: ":information_source:"}[n.Severity]
	text := strings.TrimSpace(emoji + " *" + n.Title + "*")
	if n.Body != "" {
		text += "\n" + n.Body
	}
	return map[string]any{"text": text}
}

// Deliverer sends a rendered body to a channel. It is an interface so tests
// use a fake and production uses HTTP.
type Deliverer interface {
	Deliver(ctx context.Context, channel Channel, n Notification) error
}

// HTTPDeliverer posts webhook and Slack bodies over HTTPS. It refuses private,
// loopback and link-local destinations so a configured URL cannot be used to
// reach internal services.
type HTTPDeliverer struct {
	// Client, when set, is used as-is (for tests). When nil, delivery builds
	// a client that enforces TLS and refuses non-public destinations.
	Client *http.Client
}

func (d HTTPDeliverer) Deliver(ctx context.Context, channel Channel, n Notification) error {
	var encoded []byte
	var err error
	switch channel.Kind {
	case ChannelSlack:
		encoded, err = json.Marshal(RenderSlack(n))
	case ChannelWebhook:
		encoded, err = json.Marshal(RenderWebhook(n))
	default:
		return fmt.Errorf("channel %q is not deliverable over HTTP", channel.Kind)
	}
	if err != nil {
		return err
	}
	return d.postJSON(ctx, channel.URL, channel.Secret, encoded)
}

func (d HTTPDeliverer) postJSON(ctx context.Context, rawURL, secret string, encoded []byte) error {
	target, err := url.Parse(rawURL)
	if err != nil {
		return permanent(errors.New("webhook URL is invalid"))
	}
	if target.Scheme != "https" {
		return permanent(errors.New("webhook URL must be https"))
	}
	client := d.Client
	if client == nil {
		transport := &http.Transport{
			Proxy:                 nil,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.Hostname()},
			DialContext:           safeDialContext(target.Hostname()),
			ResponseHeaderTimeout: 5 * time.Second,
			DisableCompression:    true,
		}
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(string(encoded)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "ShakerProxy-Notifications/1")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(encoded)
		request.Header.Set("X-ShakerProxy-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	response, err := client.Do(request)
	if err != nil {
		// A *url.Error spells out the full URL, which for Slack is the
		// credential itself; errors are logged and shown, so drop it.
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err := fmt.Errorf("the endpoint returned HTTP %d", response.StatusCode)
		if response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusRequestTimeout && response.StatusCode != http.StatusTooManyRequests {
			// The request itself is wrong (a revoked Slack hook is 404 or
			// 410); sending it again cannot help.
			return permanent(err)
		}
		return err
	}
	return nil
}

// permanentError marks a delivery failure that a retry cannot fix.
type permanentError struct{ error }

func (e permanentError) Unwrap() error { return e.error }

func permanent(err error) error { return permanentError{err} }

// DeliveryAttempts and DeliveryBackoff bound DeliverWithRetry: a transient
// failure (a timeout, a reset connection, HTTP 5xx or 429) is sent again
// after DeliveryBackoff, then twice that.
var (
	DeliveryAttempts = 3
	DeliveryBackoff  = 2 * time.Second
)

// DeliverWithRetry delivers n, retrying transient failures a bounded number
// of times. It returns the last error.
func DeliverWithRetry(ctx context.Context, deliverer Deliverer, channel Channel, n Notification) error {
	backoff := DeliveryBackoff
	var err error
	for attempt := 1; attempt <= DeliveryAttempts; attempt++ {
		if err = deliverer.Deliver(ctx, channel, n); err == nil {
			return nil
		}
		var fatal permanentError
		if errors.As(err, &fatal) || attempt == DeliveryAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return err
}

// safeDialContext resolves the host once and dials only a public unicast
// address, refusing loopback, private, link-local and unspecified ranges.
func safeDialContext(host string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		var lastErr error = errors.New("no usable address for the webhook host")
		for _, candidate := range resolved {
			if !isPublicUnicast(candidate.IP) {
				// The address is not named: the caller sees why, not where
				// on the internal network the name points.
				lastErr = permanent(errors.New("refusing to deliver: the webhook host resolves to a private, loopback or link-local address"))
				continue
			}
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

func isPublicUnicast(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// Block IPv4 100.64.0.0/10 (carrier-grade NAT) and the 169.254 range is
	// already link-local above.
	if four := ip.To4(); four != nil && four[0] == 100 && four[1]&0xc0 == 64 {
		return false
	}
	return true
}
