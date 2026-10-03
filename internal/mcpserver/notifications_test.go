package mcpserver

import (
	"context"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
)

func (f *fakeBackend) Notifications(context.Context) (agentapi.NotificationList, error) {
	return f.notifications, nil
}

func TestNotificationsListsReadOnly(t *testing.T) {
	backend := newFakeBackend()
	one := agentapi.Notification{ID: "ntf-1", CreatedAt: "2026-10-03T00:00:00Z", Trigger: "CLEARTEXT_EXPOSURE", Severity: "CRITICAL", Title: "Secret sent in the clear: iPhone", Body: "iPhone sent a password in the clear to login.example.com."}
	one.Subject.DeviceName = "iPhone"
	backend.notifications = agentapi.NotificationList{Unread: 1, Notifications: []agentapi.Notification{one}}

	result, _, err := (&Service{backend: backend}).notifications(context.Background(), nil, NotificationsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	var view notificationsResult
	decodeToolResult(t, result, &view)
	if view.Unread != 1 || len(view.Notifications) != 1 || view.Notifications[0].Device != "iPhone" {
		t.Fatalf("unexpected result: %#v", view)
	}
	if !strings.Contains(view.Summary, "unread") {
		t.Fatalf("summary: %q", view.Summary)
	}
	// The body must not contain a secret value.
	for _, n := range view.Notifications {
		if strings.Contains(n.Body, "hunter2") {
			t.Fatalf("notification leaked a secret: %q", n.Body)
		}
	}

	empty := newFakeBackend()
	result, _, err = (&Service{backend: empty}).notifications(context.Background(), nil, NotificationsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	var emptyView notificationsResult
	decodeToolResult(t, result, &emptyView)
	if len(emptyView.Notifications) != 0 || !strings.Contains(emptyView.Summary, "No notifications") {
		t.Fatalf("empty summary: %#v", emptyView)
	}
}
