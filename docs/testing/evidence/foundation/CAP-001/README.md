# CAP-001 capability registry evidence

Date: 2026-09-01

Environment: local macOS workspace using the repository-pinned
`golang:1.25.1-bookworm` container and Node.js 26.7.0.

Result: PASS.

Validated behavior:

- Strict parsing and cross-file revision validation.
- Required glossary coverage for every feature status.
- Required repository-local evidence and owning-document paths.
- Rejection of unknown fields and missing evidence.
- Authenticated, bounded, `no-store` capability API.
- TypeScript compilation, production build, and all 21 UI behavior tests.
- Full `make verify`, including every Go package, Compose rendering, and all
  repository security policy checks.

Commands:

```text
docker run --rm -v "$PWD":/src -w /src golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee sh -c 'gofmt -w internal/capabilityregistry/*.go tools/registrycheck/main.go apps/control-api/cmd/control-api/main.go apps/control-api/internal/server/server.go apps/control-api/internal/server/capabilities_test.go && go test ./internal/capabilityregistry ./apps/control-api/internal/server && go run ./tools/registrycheck -root .'
npm --prefix apps/web-ui run typecheck
npm --prefix apps/web-ui test
make verify
```

Known boundary: this criterion validates claim governance and presentation. It
does not promote any packet-path or interception capability.
