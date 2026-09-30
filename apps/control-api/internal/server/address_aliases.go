package server

import (
	"errors"
	"net/http"
	"os"
	"strconv"

	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

func (s *Server) listAddressAliases(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "The address alias list does not accept query parameters.")
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	aliases, err := s.inventory.ListAddressAliases()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "Address aliases are temporarily unavailable; try again.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": deviceinventory.SchemaVersion, "address_aliases": aliases})
}

type deleteAddressAliasRequest struct {
	Password         string `json:"password"`
	Reason           string `json:"reason"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

func (s *Server) deleteAddressAlias(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	aliasID := r.PathValue("aliasID")
	if !deviceinventory.ValidAddressAliasID(aliasID) {
		writeError(w, http.StatusBadRequest, "invalid_address_alias_id", "The address alias ID is invalid; list aliases with GET /api/v1/address-aliases.")
		return
	}
	operationID, ok := requestOperationID(r, deviceinventory.ValidOperationID)
	if !ok {
		writeInvalidIdempotencyKey(w)
		return
	}
	var request deleteAddressAliasRequest
	if err := decodeOptionalJSON(r, &request, 4<<10); err != nil {
		writeDecodeError(w, err, "address alias deletion")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	result, err := s.inventory.DeleteAddressAlias(aliasID, sessionUsername(r.Context()), operationID, request.ExpectedRevision, request.Reason)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "address_alias_not_found", "No address alias has this ID; list aliases with GET /api/v1/address-aliases.")
		return
	}
	if err != nil {
		s.writeDeviceMutationError(w, err)
		return
	}
	s.invalidateDeviceNames()
	s.logger.Info("address alias deleted", "username", sessionUsername(r.Context()), "address_alias_id", aliasID, "audit_id", result.Audit.ID, "replayed", result.Replayed)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listDeviceAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "device inventory is not configured")
		return
	}
	values := r.URL.Query()
	for key := range values {
		if key != "limit" && key != "before" {
			writeError(w, http.StatusBadRequest, "invalid_query", "The device audit accepts only limit and before (the next_cursor of the previous page).")
			return
		}
	}
	limit := 100
	if value := values.Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > deviceinventory.MaxAuditPageLimit {
			writeError(w, http.StatusBadRequest, "invalid_limit", "The audit limit must be between 1 and 500.")
			return
		}
		limit = parsed
	}
	page, err := s.inventory.AuditPage(limit, values.Get("before"))
	if errors.Is(err, deviceinventory.ErrAuditCursorUnavailable) {
		writeError(w, http.StatusBadRequest, "invalid_cursor", "The before cursor is not in the retained audit ledger; start again without before.")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "The device audit is temporarily unavailable; try again.")
		return
	}
	writeJSON(w, http.StatusOK, page)
}
