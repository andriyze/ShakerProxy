import assert from "node:assert/strict";
import test from "node:test";
import {performance} from "node:perf_hooks";
import {
  MAX_PENDING_LIVE_ROWS,
  MAX_VISIBLE_LIVE_ROWS,
  promoteLiveRows,
  queueLiveRows,
  virtualRowWindow,
} from "../../apps/web-ui/src/lib/liveRows.ts";

function row(index) {
  return {
    record_id: index.toString(16).padStart(64, "0"),
    occurred_at: new Date(Date.UTC(2026, 8, 1, 0, 0, 0, index)).toISOString(),
  };
}

test("live rows queue without mutating or reordering the inspected surface", () => {
  const visible = [row(3), row(2), row(1)];
  const queued = queueLiveRows([], [row(5), row(4), row(3)], new Set(visible.map((item) => item.record_id)));
  assert.deepEqual(visible.map((item) => item.record_id), [row(3), row(2), row(1)].map((item) => item.record_id));
  assert.deepEqual(queued.rows.map((item) => item.record_id), [row(5), row(4)].map((item) => item.record_id));
  assert.equal(queued.dropped, 0);
});

test("promotion caps memory and retains an inspected row", () => {
  const visible = Array.from({length: MAX_VISIBLE_LIVE_ROWS}, (_, index) => row(index + 1));
  const pending = Array.from({length: 100}, (_, index) => row(MAX_VISIBLE_LIVE_ROWS + index + 1));
  const pinned = visible.at(-1);
  const promoted = promoteLiveRows(visible, pending, new Set([pinned.record_id]));
  assert.equal(promoted.rows.length, MAX_VISIBLE_LIVE_ROWS);
  assert.equal(promoted.dropped, 100);
  assert.ok(promoted.rows.some((item) => item.record_id === pinned.record_id));
  assert.deepEqual(promoted.rows, [...promoted.rows].sort((left, right) => right.occurred_at.localeCompare(left.occurred_at) || right.record_id.localeCompare(left.record_id)));
});

test("million-row backend still computes a bounded DOM window", () => {
  for (const rowCount of [100, 1_000, 100_000, 1_000_000]) {
    const window = virtualRowWindow(rowCount, Math.max(0, rowCount * 52 - 720), 720, 52);
    assert.ok(window.end - window.start <= Math.ceil(720 / 52) + 12);
    assert.equal(window.totalSize, rowCount * 52);
    assert.ok(window.start >= 0 && window.end <= rowCount);
  }
});

test("synthetic eight-hour live model remains within hard row caps", () => {
  let visible = [];
  let pending = [];
  let dropped = 0;
  let sequence = 0;
  const started = performance.now();
  // One batch every 750 ms for eight logical hours, with ten rows per batch.
  for (let batch = 0; batch < 38_400; batch++) {
    const incoming = Array.from({length: 10}, () => row(++sequence));
    const queued = queueLiveRows(pending, incoming, new Set(visible.map((item) => item.record_id)));
    pending = queued.rows;
    dropped += queued.dropped;
    if (batch % 40 === 39) {
      const promoted = promoteLiveRows(visible, pending, new Set());
      visible = promoted.rows;
      pending = [];
      dropped += promoted.dropped;
    }
    assert.ok(visible.length <= MAX_VISIBLE_LIVE_ROWS);
    assert.ok(pending.length <= MAX_PENDING_LIVE_ROWS);
  }
  const elapsedMilliseconds = performance.now() - started;
  assert.equal(visible.length, MAX_VISIBLE_LIVE_ROWS);
  assert.equal(pending.length, 0);
  assert.ok(dropped > 0);
  console.log(JSON.stringify({logicalHours: 8, incomingRows: sequence, visibleRows: visible.length, pendingRows: pending.length, droppedFromBrowser: dropped, elapsedMilliseconds: Math.round(elapsedMilliseconds)}));
});
