const deviceIDPattern = /^device-[a-f0-9]{32}$/;
const selectedDeviceParameter = "device_id";

export function selectedDeviceFromURL(values: URLSearchParams) {
  const value = values.get(selectedDeviceParameter) ?? "";
  return deviceIDPattern.test(value) ? value : "";
}

export function applySelectedDeviceToURL(url: URL, deviceID: string) {
  const next = new URL(url);
  if (deviceIDPattern.test(deviceID)) next.searchParams.set(selectedDeviceParameter, deviceID);
  else next.searchParams.delete(selectedDeviceParameter);
  return next;
}
