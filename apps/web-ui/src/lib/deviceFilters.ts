export type DeviceListFilters = {
  view: "all" | "online" | "recent";
  q: string;
  interface: string;
  vlan_id: string;
  vendor: string;
  category: string;
  tag: string;
  ip_family: "" | "ipv4" | "ipv6";
  min_confidence: string;
  warnings: "" | "present" | "none";
  sort: "name" | "last_seen" | "first_seen" | "confidence";
  direction: "asc" | "desc";
};

export const defaultDeviceListFilters: DeviceListFilters = {
  view: "all",
  q: "",
  interface: "",
  vlan_id: "",
  vendor: "",
  category: "",
  tag: "",
  ip_family: "",
  min_confidence: "",
  warnings: "",
  sort: "last_seen",
  direction: "desc",
};

export const deviceListURLNames: {[K in keyof DeviceListFilters]: string} = {
  view: "device_view",
  q: "device_q",
  interface: "device_interface",
  vlan_id: "device_vlan",
  vendor: "device_vendor",
  category: "device_category",
  tag: "device_tag",
  ip_family: "device_ip_family",
  min_confidence: "device_min_confidence",
  warnings: "device_warnings",
  sort: "device_sort",
  direction: "device_direction",
};

export function parseDeviceListFilters(values: URLSearchParams): DeviceListFilters {
  const view = values.get(deviceListURLNames.view);
  const sort = values.get(deviceListURLNames.sort);
  const direction = values.get(deviceListURLNames.direction);
  const ipFamily = values.get(deviceListURLNames.ip_family);
  const warnings = values.get(deviceListURLNames.warnings);
  return {
    ...defaultDeviceListFilters,
    view: view === "online" || view === "recent" ? view : "all",
    q: values.get(deviceListURLNames.q) ?? "",
    interface: values.get(deviceListURLNames.interface) ?? "",
    vlan_id: values.get(deviceListURLNames.vlan_id) ?? "",
    vendor: values.get(deviceListURLNames.vendor) ?? "",
    category: values.get(deviceListURLNames.category) ?? "",
    tag: values.get(deviceListURLNames.tag) ?? "",
    ip_family: ipFamily === "ipv4" || ipFamily === "ipv6" ? ipFamily : "",
    min_confidence: values.get(deviceListURLNames.min_confidence) ?? "",
    warnings: warnings === "present" || warnings === "none" ? warnings : "",
    sort: sort === "name" || sort === "first_seen" || sort === "confidence" ? sort : "last_seen",
    direction: direction === "asc" ? "asc" : "desc",
  };
}

export function deviceListAPIPath(filters: DeviceListFilters) {
  const values = new URLSearchParams();
  for (const [key, value] of Object.entries(filters) as [keyof DeviceListFilters, string][]) {
    if (value && value !== defaultDeviceListFilters[key]) values.set(key, value);
  }
  const query = values.toString();
  return `/api/v1/devices${query ? `?${query}` : ""}`;
}

export function applyDeviceListFiltersToURL(url: URL, filters: DeviceListFilters) {
  const next = new URL(url);
  for (const [key, name] of Object.entries(deviceListURLNames) as [keyof DeviceListFilters, string][]) {
    const value = filters[key];
    if (value && value !== defaultDeviceListFilters[key]) next.searchParams.set(name, value);
    else next.searchParams.delete(name);
  }
  return next;
}
