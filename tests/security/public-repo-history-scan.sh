#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
# Replacement refs must not hide the original objects from a publication audit.
export GIT_NO_REPLACE_OBJECTS=1

# Inspect every reachable blob and every tree entry, without printing content.
# A tree-entry path is relative to the reported tree, not necessarily repo root.
repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
if [[ "$(git rev-parse --is-shallow-repository)" != false ]]; then
  echo 'public history audit requires a full git clone (fetch-depth: 0)' >&2
  exit 2
fi

scratch="$(mktemp -d "${TMPDIR:-/tmp}/shakerproxy-public-audit.XXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
max_blob_bytes=$((5 * 1024 * 1024))
failed=0

report() {
  local reason="$1" object="$2" path="$3" tree="${4:--}"
  printf 'PUBLIC-AUDIT: %s object=%s tree=%s path=%q\n' "$reason" "$object" "$tree" "$path" >&2
  failed=1
}

sensitive_path() {
  local lower
  lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    *.env.example|*.env.sample|*.env.template) return 1 ;;
    *.p12|*.pfx|*.kdbx|*.pcap|*.pcapng|*.har|*.sqlite|*.sqlite3|*.key|*.env) return 0 ;;
  esac
  return 1
}

# Assemble signatures so the scanner and its synthetic tests need no exemption.
patterns=(
  '-----BEGIN .*PRIVATE'' KEY-----'
  'AKIA''[0-9A-Z]{16}'
  'gh[pousr]_[A-Za-z0-9_]{20,}'
  'github_pat_[A-Za-z0-9_]{20,}'
  'xox[baprs]-[A-Za-z0-9-]{20,}'
  'AIza''[0-9A-Za-z_-]{35}'
  'sk_live_[0-9A-Za-z]{16,}'
)
pattern="$(IFS='|'; echo "${patterns[*]}")"

# Materialize checked command outputs: a process-substitution failure must not
# turn an incomplete inventory into a passing audit. Names are read from trees
# with NUL framing; rev-list emits each object only once, not every historic path.
git rev-list --objects --all --no-object-names > "$scratch/objects"
[[ -s "$scratch/objects" ]] || { echo 'public history audit has no reachable objects to inspect' >&2; exit 2; }
git cat-file --batch-check='%(objectname) %(objecttype) %(objectsize)' < "$scratch/objects" > "$scratch/inventory"

while IFS=' ' read -r object type size; do
  [[ "$size" =~ ^[0-9]+$ ]] || { echo 'public history audit could not inspect an object' >&2; exit 2; }
  case "$type" in
    tree)
      git ls-tree -z "$object" > "$scratch/entries"
      while IFS= read -r -d '' entry; do
        metadata="${entry%%$'\t'*}"
        path="${entry#*$'\t'}"
        IFS=' ' read -r _ entry_type child <<< "$metadata"
        if [[ "$entry_type" == blob ]] && sensitive_path "$path"; then
          report 'sensitive historical filename' "$child" "$path" "$object"
        fi
      done < "$scratch/entries"
      ;;
    blob)
      if ((size > max_blob_bytes)); then
        report 'blob exceeds audit size limit; manual review required' "$object" '<blob>'
        continue
      fi
      # No grep -q pipeline: early reader exit plus pipefail caused false passes.
      # Scan binary bytes too. Keep the temporary copy private and never echo it.
      git cat-file blob "$object" > "$scratch/blob"
      if grep -Ea -- "$pattern" "$scratch/blob" >/dev/null; then
        report 'high-confidence credential/private-key signature' "$object" '<blob>'
      else
        status=$?
        ((status == 1)) || { echo 'public history audit content scan failed' >&2; exit 2; }
      fi
      ;;
    commit|tag) ;;
    *) echo 'public history audit encountered an unsupported object type' >&2; exit 2 ;;
  esac
done < "$scratch/inventory"

if ((failed != 0)); then
  echo 'Public repository history audit FAILED. Review flagged objects; rotate actual secrets and remove prohibited artifacts before publication.' >&2
  exit 1
fi

echo 'Public repository history audit passed for reachable Git objects and the configured signatures/filename rules.'
echo 'This does not cover external LFS payloads, submodule contents, release assets, or credentials outside these signatures.'
