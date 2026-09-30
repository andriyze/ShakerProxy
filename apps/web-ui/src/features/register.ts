// Idempotent registration helpers: a module evaluated twice (for example
// during hot reload) must not register the same entry twice.
import { deviceExtensions, featureViews, planExtensions, type DeviceExtension, type FeatureView, type PlanExtension } from "./registry"

export function registerView(view: FeatureView): void {
  const index = featureViews.findIndex((item) => item.id === view.id)
  if (index >= 0) featureViews[index] = view
  else featureViews.push(view)
}

export function registerPlanExtension(extension: PlanExtension): void {
  const index = planExtensions.findIndex((item) => item.id === extension.id)
  if (index >= 0) planExtensions[index] = extension
  else planExtensions.push(extension)
}

export function registerDeviceExtension(extension: DeviceExtension): void {
  const index = deviceExtensions.findIndex((item) => item.id === extension.id)
  if (index >= 0) deviceExtensions[index] = extension
  else deviceExtensions.push(extension)
}
