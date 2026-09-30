package server

import (
	"errors"
	"reflect"
)

const maxDeletionCopyBoundaries = 8

type deletionCopyBoundary struct {
	DataClass         string `json:"data_class"`
	Backend           string `json:"backend"`
	Configured        bool   `json:"configured"`
	ObjectCount       int    `json:"object_count"`
	CountExact        bool   `json:"count_exact"`
	DeletionAvailable bool   `json:"deletion_available"`
	Disposition       string `json:"disposition"`
	Warning           string `json:"warning"`
}

func deletionCopyBoundaries(exportAuditRecords int) []deletionCopyBoundary {
	return []deletionCopyBoundary{
		{DataClass: "capture_export_audit", Backend: "control_api_export_ledger", Configured: true, ObjectCount: exportAuditRecords, CountExact: true, Disposition: "RETAINED_AUDIT", Warning: "Delivery records are retained as administrative audit evidence; they do not contain exported packet bytes."},
		{DataClass: "local_export_artifacts", Backend: "local_export_store", ObjectCount: 0, CountExact: true, Disposition: "NOT_CONFIGURED", Warning: "This build streams capture exports to the requesting client and does not retain a managed local export artifact."},
		{DataClass: "existing_backups", Backend: "local_backup_store", ObjectCount: 0, CountExact: true, Disposition: "NOT_CONFIGURED", Warning: "No ShakerProxy-managed local backup store is configured in this build."},
		{DataClass: "arkime_index", Backend: "arkime", ObjectCount: 0, CountExact: true, Disposition: "NOT_CONFIGURED", Warning: "The optional Arkime backend is not configured and contributes zero managed objects."},
		{DataClass: "opensearch_index", Backend: "opensearch", ObjectCount: 0, CountExact: true, Disposition: "NOT_CONFIGURED", Warning: "The optional OpenSearch backend is not configured and contributes zero managed objects."},
		{DataClass: "external_exported_copies", Backend: "outside_appliance", ObjectCount: 0, CountExact: false, Disposition: "OUTSIDE_APPLIANCE_CONTROL", Warning: "Copies already delivered to clients or copied outside ShakerProxy cannot be enumerated or erased by this appliance."},
	}
}

func validateDeletionCopyBoundaries(boundaries []deletionCopyBoundary, exportAuditRecords int) error {
	if len(boundaries) == 0 {
		// Schema-2 previews persisted before copy-boundary enumeration remain
		// readable and executable with their original digest.
		return nil
	}
	if len(boundaries) > maxDeletionCopyBoundaries || exportAuditRecords < 0 || !reflect.DeepEqual(boundaries, deletionCopyBoundaries(exportAuditRecords)) {
		return errors.New("deletion copy boundaries do not match configured stores")
	}
	return nil
}
