import { ApiError, authorizationHeaders, endSessionIfUnauthorized, errorMessage } from "../api"

// authFetch is for the few requests that need the raw Response (streams,
// response headers such as X-ShakerProxy-SHA256). Everything else uses api() or
// apiBlob() from ../api. A 401 ends the session exactly like api() does.
export async function authFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = authorizationHeaders(init.headers)
  if (init.body && typeof init.body === "string" && !headers.has("Content-Type"))
    headers.set("Content-Type", "application/json")
  const response = await fetch(path, { cache: "no-store", credentials: "same-origin", ...init, headers })
  if (response.status === 401) {
    const body = await response
      .clone()
      .json()
      .catch(() => ({}))
    endSessionIfUnauthorized(401, errorMessage(body, 401).code)
  }
  return response
}

// responseError converts a failed Response into an ApiError with the server's
// human-readable message.
export async function responseError(response: Response): Promise<ApiError> {
  const body = await response.json().catch(() => ({}))
  const { message, code } = errorMessage(body, response.status)
  return new ApiError(message, response.status, code)
}
