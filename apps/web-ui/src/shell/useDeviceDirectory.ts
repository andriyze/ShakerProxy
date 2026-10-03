import { api } from "../api"
import { deviceDirectory, type DeviceDirectory } from "../lib/deviceTitle"
import type { InventorySnapshot } from "../types"
import { useResource } from "./hooks"

// useDeviceDirectory loads the device inventory once a minute so pages that
// list traffic can title each event's device "<name> · <IPv4>". Without it
// (still loading, or no access) callers fall back to the event's own fields.
export function useDeviceDirectory(): DeviceDirectory | undefined {
  const inventory = useResource(
    async (signal) => {
      const result = await api<InventorySnapshot>("/api/v1/devices", { signal })
      return deviceDirectory(Array.isArray(result.devices) ? result.devices : [], result.platform_hints ?? {}, result.service_hints ?? {})
    },
    [],
    { intervalMs: 60_000 },
  )
  return inventory.data ?? undefined
}
