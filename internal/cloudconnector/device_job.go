package cloudconnector

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	JobDeviceRename        = "device.rename"
	DeviceNamingCapability = "device.naming"
)

type DeviceRenameParameters struct {
	LocalDeviceID string `json:"local_device_id"`
	FriendlyName  string `json:"friendly_name"`
}

func ValidateDeviceRenameJob(job CloudJob, state State, appliedRevision uint64, capabilities []string, now time.Time) (DeviceRenameParameters, error) {
	if strings.TrimSpace(job.ID) == "" || len(job.ID) > 64 || strings.TrimSpace(job.IdempotencyKey) == "" || len(job.IdempotencyKey) > 128 {
		return DeviceRenameParameters{}, errors.New("device rename job identity is invalid")
	}
	if job.SensorID != state.SensorID || job.OrganizationID != state.OrganizationID {
		return DeviceRenameParameters{}, errors.New("device rename job does not belong to this sensor")
	}
	if job.Type != JobDeviceRename || job.RequiredCapability != DeviceNamingCapability || !containsCapability(capabilities, DeviceNamingCapability) {
		return DeviceRenameParameters{}, errors.New("device rename job capability is invalid")
	}
	if job.ApprovalState != "NOT_REQUIRED" && job.ApprovalState != "APPROVED" {
		return DeviceRenameParameters{}, errors.New("device rename job is not approved")
	}
	if job.ExpiresAt.IsZero() || !job.ExpiresAt.After(now) || job.ExpiresAt.After(now.Add(2*time.Hour)) {
		return DeviceRenameParameters{}, errors.New("device rename job expiry is outside the accepted window")
	}
	if job.CreatedAt.IsZero() || job.CreatedAt.After(now.Add(2*time.Minute)) || job.CreatedAt.Before(now.Add(-24*time.Hour)) {
		return DeviceRenameParameters{}, errors.New("device rename job creation time is outside the accepted window")
	}
	if job.ExpectedRevision != nil && *job.ExpectedRevision != appliedRevision {
		return DeviceRenameParameters{}, errors.New("device rename job expected revision does not match")
	}
	parameters, err := parseDeviceRenameParameters(job.Parameters)
	if err != nil {
		return DeviceRenameParameters{}, err
	}
	return parameters, nil
}

func parseDeviceRenameParameters(values map[string]any) (DeviceRenameParameters, error) {
	if len(values) != 2 {
		return DeviceRenameParameters{}, errors.New("device rename job contains unsupported parameters")
	}
	localDeviceID, ok := values["local_device_id"].(string)
	if !ok {
		return DeviceRenameParameters{}, errors.New("device rename local device ID is missing")
	}
	friendlyName, ok := values["friendly_name"].(string)
	if !ok {
		return DeviceRenameParameters{}, errors.New("device rename friendly name is missing")
	}
	parameters := DeviceRenameParameters{
		LocalDeviceID: strings.TrimSpace(localDeviceID),
		FriendlyName:  strings.TrimSpace(friendlyName),
	}
	if parameters.LocalDeviceID == "" || len(parameters.LocalDeviceID) > 128 || parameters.FriendlyName == "" || len(parameters.FriendlyName) > 128 {
		return DeviceRenameParameters{}, errors.New("device rename parameters are invalid")
	}
	return parameters, nil
}

func ExecuteDeviceRenameJob(ctx context.Context, store *DeviceRuntimeStore, parameters DeviceRenameParameters) (map[string]any, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if store == nil {
		return nil, errors.New("device runtime store is unavailable")
	}
	record, err := store.Rename(parameters.LocalDeviceID, parameters.FriendlyName)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"local_device_id": record.LocalDeviceID,
		"friendly_name":   record.FriendlyName,
		"platform":        record.Platform,
		"updated_at":      record.UpdatedAt,
	}, nil
}
