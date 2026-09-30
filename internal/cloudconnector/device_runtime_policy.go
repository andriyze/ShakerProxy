package cloudconnector

import "shakerproxy.dev/shakerproxy/internal/trafficpolicy"

func mergeTrafficPolicyDeviceRuntime(runtime trafficpolicy.Runtime, store *DeviceRuntimeStore) trafficpolicy.Runtime {
	if store == nil {
		return runtime
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		return runtime
	}
	runtime.DevicePlatforms = snapshot.DevicePlatforms
	runtime.DeviceIPv4 = snapshot.DeviceIPv4
	runtime.DeviceIPv6 = snapshot.DeviceIPv6
	return runtime
}
