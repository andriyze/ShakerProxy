// Helpers for source-level UI assertions. The dashboard shell is split across
// many modules, so tests read either one module or every shell module at once.
// Whitespace runs (including the line breaks a formatter inserts inside long
// JSX text) are collapsed to one space so assertions match wording, not layout.
import { readFileSync, readdirSync, statSync } from "node:fs"

const SRC = new URL("../../apps/web-ui/src/", import.meta.url)

export function webUIFile(path) {
  return readFileSync(new URL(path, SRC), "utf8").replace(/\s+/g, " ")
}

function walk(url, prefix, out) {
  for (const name of readdirSync(url).sort()) {
    const child = new URL(name, url)
    if (statSync(child).isDirectory()) {
      // Feature modules are owned separately and have their own tests.
      if (prefix === "" && name === "features") continue
      walk(new URL(`${name}/`, url), `${prefix}${name}/`, out)
    } else if (/\.(ts|tsx)$/.test(name)) {
      out.push(`${prefix}${name}`)
    }
  }
  return out
}

// webUIFiles lists every shell source file relative to apps/web-ui/src.
export function webUIFiles() {
  return walk(SRC, "", [])
}

// webUISource concatenates every shell source file (excluding src/features).
export function webUISource() {
  return webUIFiles()
    .map((path) => webUIFile(path))
    .join("\n")
}
