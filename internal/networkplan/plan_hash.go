package networkplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// CanonicalPlanHash returns the SHA-256 plan hash over the canonical typed JSON
// (with the Wi-Fi password replaced by its pre-shared key), exactly as Validate
// computes it for a valid plan. Recovery uses it to prove that a persisted
// plan still matches the hash its preview and confirmation were bound to.
func CanonicalPlanHash(plan Plan) string {
	canonical, _ := json.Marshal(hashablePlan(plan))
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}
