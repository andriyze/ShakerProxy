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
		return err
	}
	if target.Scheme != "https" {
		return errors.New("webhook URL must be https")
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
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("the endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
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
				lastErr = fmt.Errorf("refusing to deliver to non-public address %s", candidate.IP)
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
