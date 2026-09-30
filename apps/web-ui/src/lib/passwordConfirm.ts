// On-demand administrator password confirmation (pure logic; the dialog is
// shell/passwordPrompt.tsx).
//
// Most changes carry no password: the appliance accepts them for ten minutes
// after the password was last confirmed in this session (signing in counts).
// Outside that window it answers 401 reauthentication_required, and actions
// that always need it answer 401 password_required. withPassword() then asks
// once and retries the same request with the password.

export const PASSWORD_CANCELLED = "Cancelled. Nothing was changed."

export class PasswordCancelled extends Error {
  constructor() {
    super(PASSWORD_CANCELLED)
    this.name = "PasswordCancelled"
  }
}

export type PasswordRequest = { action: string; error: string }
export type PasswordPrompter = (request: PasswordRequest) => Promise<string | null>

let prompter: PasswordPrompter | null = null

// registerPasswordPrompter installs the dialog (or a test double) and returns
// a function that removes it again.
export function registerPasswordPrompter(next: PasswordPrompter): () => void {
  prompter = next
  return () => {
    if (prompter === next) prompter = null
  }
}

type StatusError = { status?: unknown; code?: unknown }

function asStatusError(reason: unknown): StatusError {
  return reason && typeof reason === "object" ? (reason as StatusError) : {}
}

// passwordNeeded reports whether an error asks for the administrator password.
export function passwordNeeded(reason: unknown): boolean {
  const { status, code } = asStatusError(reason)
  return status === 401 && (code === "reauthentication_required" || code === "password_required")
}

export function wrongPassword(reason: unknown): boolean {
  const { status, code } = asStatusError(reason)
  return status === 401 && code === "reauthentication_failed"
}

// withPassword runs an action without a password first (or with the one
// already typed into the form); if the appliance asks for one, it prompts and
// retries until the action succeeds, fails for another reason, or the person
// cancels (PasswordCancelled).
export async function withPassword<T>(
  action: string,
  run: (password?: string) => Promise<T>,
  initialPassword?: string,
): Promise<T> {
  let password = initialPassword || undefined
  for (;;) {
    try {
      return await run(password)
    } catch (reason) {
      let error: string
      if (passwordNeeded(reason)) error = ""
      else if (wrongPassword(reason) && password !== undefined) error = "That password is not correct. Try again."
      else throw reason
      if (!prompter) throw reason
      const next = await prompter({ action, error })
      if (next === null) throw new PasswordCancelled()
      password = next
    }
  }
}
