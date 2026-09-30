export const MAX_VISIBLE_LIVE_ROWS = 1_000;
export const MAX_PENDING_LIVE_ROWS = 500;
export const LIVE_ROW_OVERSCAN = 6;

export type LiveRowIdentity = {
  record_id: string;
  occurred_at: string;
};

export type QueuedLiveRows<T extends LiveRowIdentity> = {
  rows: T[];
  dropped: number;
};

export type PromotedLiveRows<T extends LiveRowIdentity> = {
  rows: T[];
  dropped: number;
};

export type VirtualRowWindow = {
  start: number;
  end: number;
  offset: number;
  totalSize: number;
};

function newestFirst(left: LiveRowIdentity, right: LiveRowIdentity) {
  return right.occurred_at.localeCompare(left.occurred_at) || right.record_id.localeCompare(left.record_id);
}

function uniqueNewest<T extends LiveRowIdentity>(rows: readonly T[]) {
  const unique = new Map<string, T>();
  for (const row of rows) {
    if (!unique.has(row.record_id)) unique.set(row.record_id, row);
  }
  return Array.from(unique.values()).sort(newestFirst);
}

export function queueLiveRows<T extends LiveRowIdentity>(
  pending: readonly T[],
  incoming: readonly T[],
  visibleRecordIDs: ReadonlySet<string>,
  limit = MAX_PENDING_LIVE_ROWS,
): QueuedLiveRows<T> {
  if (!Number.isSafeInteger(limit) || limit < 1) throw new Error("pending live-row limit is invalid");
  const candidates = uniqueNewest([...incoming, ...pending]).filter((row) => !visibleRecordIDs.has(row.record_id));
  return {rows: candidates.slice(0, limit), dropped: Math.max(0, candidates.length - limit)};
}

export function promoteLiveRows<T extends LiveRowIdentity>(
  visible: readonly T[],
  pending: readonly T[],
  pinnedRecordIDs: ReadonlySet<string>,
  limit = MAX_VISIBLE_LIVE_ROWS,
): PromotedLiveRows<T> {
  if (!Number.isSafeInteger(limit) || limit < 1) throw new Error("visible live-row limit is invalid");
  const all = uniqueNewest([...pending, ...visible]);
  const kept = all.slice(0, limit);
  const keptIDs = new Set(kept.map((row) => row.record_id));
  for (const pinnedID of pinnedRecordIDs) {
    if (keptIDs.has(pinnedID)) continue;
    const pinned = all.find((row) => row.record_id === pinnedID);
    if (!pinned) continue;
    let replace = kept.length - 1;
    while (replace >= 0 && pinnedRecordIDs.has(kept[replace]?.record_id ?? "")) replace--;
    if (replace < 0) break;
    keptIDs.delete(kept[replace]?.record_id ?? "");
    kept[replace] = pinned;
    keptIDs.add(pinnedID);
  }
  kept.sort(newestFirst);
  return {rows: kept, dropped: Math.max(0, all.length - kept.length)};
}

export function virtualRowWindow(
  rowCount: number,
  scrollTop: number,
  viewportHeight: number,
  rowHeight: number,
  overscan = LIVE_ROW_OVERSCAN,
): VirtualRowWindow {
  if (![rowCount, scrollTop, viewportHeight, rowHeight, overscan].every(Number.isFinite) || !Number.isSafeInteger(rowCount) || rowCount < 0 || scrollTop < 0 || viewportHeight < 0 || rowHeight <= 0 || !Number.isSafeInteger(overscan) || overscan < 0) {
    throw new Error("virtual live-row window input is invalid");
  }
  const firstVisible = Math.min(rowCount, Math.floor(scrollTop / rowHeight));
  const visibleCount = Math.ceil(viewportHeight / rowHeight);
  const start = Math.max(0, firstVisible - overscan);
  const end = Math.min(rowCount, firstVisible + visibleCount + overscan);
  return {start, end, offset: start * rowHeight, totalSize: rowCount * rowHeight};
}
