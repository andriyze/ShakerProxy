export type DeletionBackendState = "NOT_STARTED" | "RUNNING" | "COMPLETED" | "FAILED";

export type DeletionBackendSummary = {
  backend: "normalized_events" | "zeek_checkpoint" | "suricata_checkpoint" | "host_capture_artifacts";
  state: DeletionBackendState;
};

export function captureArtifactsWereDeleted(job: {backends: DeletionBackendSummary[]}): boolean {
  return Array.isArray(job.backends) && job.backends.some((backend) => backend.backend === "host_capture_artifacts" && backend.state === "COMPLETED");
}

export function captureDeletionCanRetry(state: string): boolean {
  return state === "PARTIAL" || state === "FAILED";
}

export function captureDeletionCanCancel(job: {state: string; backends: DeletionBackendSummary[]}): boolean {
  return job.state === "PENDING" && Array.isArray(job.backends) && job.backends.length > 0 && job.backends.every((backend) => backend.state === "NOT_STARTED");
}

export function coordinatedDeletionRequest<T>(preview: T, password: FormDataEntryValue | null, confirmation: FormDataEntryValue | null) {
  return {password, preview, confirmation};
}

export function deletionBackendLabel(backend: DeletionBackendSummary["backend"]): string {
  if (backend === "normalized_events") return "Normalized events and ingest spool";
  if (backend === "zeek_checkpoint") return "Zeek analyzer checkpoint";
  if (backend === "suricata_checkpoint") return "Suricata analyzer checkpoint";
  return "PCAP and capture-session files";
}
