import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const ignoredDirectories = new Set([".cache", ".claude", ".git", ".local", "dist", "node_modules"]);

function markdownFiles(directory) {
  const result = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...markdownFiles(absolute));
    else if (entry.isFile() && extname(entry.name) === ".md") result.push(absolute);
  }
  return result;
}

function relative(absolute) {
  return absolute.slice(root.length + 1);
}

const makefile = readFileSync(join(root, "Makefile"), "utf8");
const makeTargets = new Set(
  [...makefile.matchAll(/^([A-Za-z0-9_.-]+):/gm)].map((match) => match[1]),
);
const failures = [];
const files = markdownFiles(root).sort();

for (const file of files) {
  const document = readFileSync(file, "utf8");
  const lines = document.split("\n");
  const display = relative(file);
  if (!lines[0]?.startsWith("# ")) failures.push(`${display}:1: document must start with one H1`);

  let fence = null;
  const headings = new Map();
  for (const [offset, line] of lines.entries()) {
    const lineNumber = offset + 1;
    if (/[ \t]+$/.test(line)) failures.push(`${display}:${lineNumber}: trailing whitespace`);

    const fenceMatch = /^```([^ ]*)\s*$/.exec(line);
    if (fenceMatch) {
      fence = fence === null ? fenceMatch[1].toLowerCase() : null;
      continue;
    }
    if (fence !== null && /^(bash|console|sh|shell|text|zsh)?$/.test(fence)) {
      const command = /^\s*(?:sudo\s+)?make\s+([A-Za-z0-9_.-]+)/.exec(line);
      if (command && !makeTargets.has(command[1])) {
        failures.push(`${display}:${lineNumber}: unknown Make target ${command[1]}`);
      }
    }

    const heading = /^(#{1,6})\s+(.+)$/.exec(line);
    if (heading) {
      const identity = `${heading[1].length}:${heading[2].trim().toLowerCase()}`;
      if (headings.has(identity)) {
        failures.push(`${display}:${lineNumber}: duplicate heading (first at ${headings.get(identity)})`);
      } else {
        headings.set(identity, lineNumber);
      }
    }
  }
  if (fence !== null) failures.push(`${display}:${lines.length}: unclosed fenced block`);

  for (const match of document.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)) {
    let target = match[1].trim().replace(/^<|>$/g, "").split(/\s+[\"']/)[0];
    if (!target || /^(https?:|mailto:|#)/.test(target)) continue;
    target = decodeURIComponent(target.split("#", 1)[0]);
    const destination = isAbsolute(target) ? target : resolve(dirname(file), target);
    if (!statExists(destination)) {
      const lineNumber = document.slice(0, match.index).split("\n").length;
      failures.push(`${display}:${lineNumber}: missing local link target ${match[1]}`);
    }
  }
}

function statExists(path) {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(`documentation check passed (${files.length} Markdown files)`);
