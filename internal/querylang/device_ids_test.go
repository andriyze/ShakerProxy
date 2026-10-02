package querylang

import (
	"fmt"
	"strings"
	"testing"
)

// The Devices page filters a device's traffic to its own ID plus up to 16
// records merged into it; the longest such query must stay within bounds.
func TestDeviceQueryWithFormerIDsParses(t *testing.T) {
	ids := []string{}
	for index := 0; index < 17; index++ {
		ids = append(ids, fmt.Sprintf("device.id:device-%032x", index+1))
	}
	query := "time:last_24h AND ((" + strings.Join(ids, " OR ") + "))"
	if _, err := Parse(query); err != nil {
		t.Fatalf("device query with former IDs was rejected: %v", err)
	}
}
