package agentapi

import (
	"context"
	"errors"
)

const maxAgentNotificationBytes = 256 << 10

// Notification is one in-app notification. It states what happened and the
// subject; it never contains a secret value.
type Notification struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	Trigger   string `json:"trigger"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Read      bool   `json:"read"`
	Subject   struct {
		DeviceID   string `json:"device_id,omitempty"`
		DeviceName string `json:"device_name,omitempty"`
		Host       string `json:"host,omitempty"`
		Kind       string `json:"kind,omitempty"`
	} `json:"subject"`
}

// NotificationList is the read-only in-app notification list.
type NotificationList struct {
	Unread        int            `json:"unread"`
	Notifications []Notification `json:"notifications"`
}

// Notifications reads the recent in-app notifications.
func (c *Client) Notifications(ctx context.Context) (NotificationList, error) {
	if c == nil || c.base == nil || c.client == nil {
		return NotificationList{}, errors.New("agent API client is unavailable")
	}
	var list NotificationList
	if _, err := c.getJSONWith(ctx, "/api/v1/notifications?limit=50", nil, maxAgentNotificationBytes, &list, false); err != nil {
		return NotificationList{}, err
	}
	if len(list.Notifications) > 200 {
		return NotificationList{}, errors.New("agent notifications API returned too many entries")
	}
	return list, nil
}
