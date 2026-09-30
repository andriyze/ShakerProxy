export type DeviceTrafficDeletionChoice =
  | "DELETE_METADATA_ONLY"
  | "DELETE_DERIVED_CONTENT_ONLY"
  | "DELETE_WHOLE_CAPTURE_FILES"
  | "SANITIZE_AND_REWRITE_PCAP";

export type DeviceTrafficChoicePresentation = {
  title: string;
  effect: string;
  packetBoundary: string;
};

const presentations: Record<DeviceTrafficDeletionChoice, DeviceTrafficChoicePresentation> = {
  DELETE_METADATA_ONLY: {
    title: "Delete metadata only",
    effect: "Removes the frozen searchable event rows when coordinated execution is available.",
    packetBoundary: "Raw packet bytes remain in shared PCAP files.",
  },
  DELETE_DERIVED_CONTENT_ONLY: {
    title: "Delete derived content only",
    effect: "Removes selected normalized events and analyzer checkpoints from every configured derived backend.",
    packetBoundary: "Raw packet bytes remain in shared PCAP files.",
  },
  DELETE_WHOLE_CAPTURE_FILES: {
    title: "Delete whole capture files",
    effect: "Removes each impacted shared capture file and all normalized metadata for its affected capture session.",
    packetBoundary: "Unrelated retained packets and session-level searchable metadata are explicit collateral.",
  },
  SANITIZE_AND_REWRITE_PCAP: {
    title: "Sanitize and rewrite PCAP",
    effect: "Creates and verifies replacements that exclude only the selected packets.",
    packetBoundary: "Requires temporary capacity and coordinated analyzer/search re-indexing.",
  },
};

export function deviceTrafficChoicePresentation(choice: DeviceTrafficDeletionChoice): DeviceTrafficChoicePresentation {
  return presentations[choice];
}

export function deviceTrafficPreviewState(preview: {exact_impact: boolean; pcap: {blockers: unknown[]}}): "EXACT" | "BLOCKED" {
  return preview.exact_impact && preview.pcap.blockers.length === 0 ? "EXACT" : "BLOCKED";
}

export function deviceTrafficChoiceCanExecute(choice: {eligible: boolean; execution_available: boolean}): boolean {
  return choice.eligible && choice.execution_available;
}
