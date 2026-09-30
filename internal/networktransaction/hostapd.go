package networktransaction

import "errors"

// validateAccessPoint checks the Wi-Fi access point part of a rollback
// snapshot. A plan without Wi-Fi records nothing; a Wi-Fi plan records whether
// the ShakerProxy hostapd configuration existed so rollback can restore it exactly.
func (r RollbackSpec) validateAccessPoint() error {
	if !r.HostapdManaged {
		if r.HostapdConfigExisted || r.HostapdConfigSHA256 != "" || r.HostapdConfigMode != 0 {
			return errors.New("access point backup metadata requires a managed access point")
		}
		return nil
	}
	if r.HostapdConfigExisted {
		if !planHashPattern.MatchString(r.HostapdConfigSHA256) || r.HostapdConfigMode&^0o777 != 0 {
			return errors.New("access point configuration backup metadata is invalid")
		}
	} else if r.HostapdConfigSHA256 != "" || r.HostapdConfigMode != 0 {
		return errors.New("absent access point configuration cannot have backup metadata")
	}
	return nil
}
