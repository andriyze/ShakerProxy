import { authFetch, responseError } from "../../shell/authFetch"
import type { LiveEventBatch } from "../../types"

export async function consumeLiveEventStream(
  path: string,
  signal: AbortSignal,
  onOpen: () => void,
  onBatch: (batch: LiveEventBatch) => void,
) {
  // A 401 here ends the session like any other request (authFetch).
  const response = await authFetch(path, { headers: { Accept: "text/event-stream" }, signal })
  if (!response.ok) throw await responseError(response)
  if (!response.headers.get("Content-Type")?.toLowerCase().startsWith("text/event-stream") || !response.body)
    throw new Error("The event service returned an invalid live stream")
  onOpen()
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ""
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n")
    if (buffer.length > 512 * 1024) throw new Error("The live event stream exceeded its frame limit")
    let boundary = buffer.indexOf("\n\n")
    while (boundary >= 0) {
      const frame = buffer.slice(0, boundary)
      buffer = buffer.slice(boundary + 2)
      const lines = frame.split("\n")
      const eventName = lines
        .find((line) => line.startsWith("event:"))
        ?.slice(6)
        .trim()
      const data = lines
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).trimStart())
        .join("\n")
      if (eventName === "events" && data) {
        const batch = JSON.parse(data) as LiveEventBatch
        if (
          batch.schema !== 1 ||
          !Array.isArray(batch.events) ||
          batch.events.length > 100 ||
          typeof batch.next_cursor !== "string" ||
          batch.next_cursor.length > 256
        )
          throw new Error("The event service returned an invalid live batch")
        onBatch(batch)
      }
      boundary = buffer.indexOf("\n\n")
    }
  }
}
