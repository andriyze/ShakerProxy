# Public repository history audit

Before changing this repository from private to public, run:

```bash
tests/security/public-repo-history-scan.sh
```

The command must run from a **full clone**. CI checks out the entire reachable history with `fetch-depth: 0` for this gate.

The scanner intentionally reports only Git object IDs and historical paths. It does not print matched credential material. It blocks high-confidence private-key and token signatures and sensitive historical artifacts such as `.env`, private key containers, packet captures, HAR files, password vaults, and SQLite databases.

A failure is a visibility blocker. Rotate any exposed credential first, remove the sensitive object from reachable Git history with an explicit history-rewrite procedure, then rerun the audit before making the repository public.
