package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type NotificationsArgs struct{}

type notificationLine struct {
	CreatedAt string `json:"created_at"`
	Severity  string `json:"severity"`
	Trigger   string `json:"trigger"`
	Title     string `json:"title"`
	Body      string `json:"body,omitempty"`
	Device    string `json:"device,omitempty"`
	Read      bool   `json:"read"`
}

type notificationsResult struct {
	Summary       string             `json:"summary"`
	Unread        int                `json:"unread"`
	Notifications []notificationLine `json:"notifications"`
}

// notifications lists the recent in-app notifications. It is read-only: there
// is no MCP action to configure channels or rules. A notification states what
// happened and the subject, never a secret value.
func (s *Service) notifications(ctx context.Context, _ *mcp.CallToolRequest, _ NotificationsArgs) (*mcp.CallToolResult, any, error) {
	list, err := s.backend.Notifications(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read notifications: %w", err)
	}
	result := notificationsResult{Unread: list.Unread, Notifications: []notificationLine{}}
	for index, n := range list.Notifications {
		if index >= 50 {
			break
		}
		device := n.Subject.DeviceName
		if device == "" {
			device = n.Subject.DeviceID
		}
		result.Notifications = append(result.Notifications, notificationLine{
			CreatedAt: n.CreatedAt, Severity: n.Severity, Trigger: n.Trigger,
			Title: boundText(n.Title, 200), Body: boundText(n.Body, 400), Device: device, Read: n.Read,
		})
	}
	if len(result.Notifications) == 0 {
		result.Summary = "No notifications. Configure channels and rules in Integrations to be alerted about new devices, bypassing devices, cleartext secrets and flagged domains."
	} else {
		result.Summary = boundText(fmt.Sprintf("%d notification(s), %d unread. Newest: %s", len(result.Notifications), list.Unread, result.Notifications[0].Title), 400)
	}
	return textResult(result)
}
