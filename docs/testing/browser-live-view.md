# Live-view browser-state evidence

ShakerProxy's normalized traffic UI uses two independent browser caps:

- 500 unique summaries waiting behind the explicit `Show new events` action.
- 1,000 visible summaries after promotion.

Incoming SSE batches do not mutate or reorder the inspected surface. Promotion
deduplicates immutable record IDs, retains the selected record when it would
otherwise age out, and reports every row evicted from browser memory. The
windowed table calculates only the visible rows plus six rows of overscan above
and below the viewport. Arrow keys, Home, End, and Escape operate through one
focusable row group rather than adding 1,000 tab stops.

Run the deterministic model evidence with:

```bash
npm --prefix apps/web-ui test
```

The 2026-09-01 development run under Node 26.7 processed 384,000 unique rows—ten
rows every 750 ms for eight logical hours—in about 1.7 seconds. It ended with
exactly 1,000 visible rows, no pending rows, and 383,000 explicitly counted
browser evictions. Separate 100, 1,000, 100,000, and 1,000,000-row calculations
kept a 720 px viewport to at most 26 row elements.

A production-container browser pass on the same date loaded 60 stored events,
rendered 14 rows in a 560 px viewport, moved selection to the final row with
the End key, and kept the inspector open across promotion of 20 streamed
events. Manual pause changed the stream to `PAUSED`; resume returned it to
`LIVE`. At a 320 px breakpoint the document remained 320 px wide while the
traffic viewport exposed its 540 px table through an internal horizontal
scroller. No browser console errors were recorded after the fixes.

This is deterministic state-model and high-cardinality windowing evidence, not
an eight-hour wall-clock browser claim. A reference-hardware Chromium and Firefox
soak must still measure heap growth, detached nodes, long tasks, visual lag, and
resume behavior before Phase 3 or the browser performance budget can be marked
complete.
