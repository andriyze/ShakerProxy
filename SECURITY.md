# Security policy

ShakerProxy is pre-release software. Releases are intended for evaluation and controlled testing, not as a sole security boundary for production networks. TLS interception changes the trust model of enrolled clients and should only be enabled on networks and devices you are authorized to inspect.

## Reporting a vulnerability

Do not publish exploit details, credentials, packet captures, private keys, TLS key logs, personal data, or sensitive customer traffic in a public issue.

Report vulnerabilities privately through GitHub's **Security → Report a vulnerability** flow. If private vulnerability reporting is unavailable, open a minimal public issue titled `Security contact requested` without technical details or sensitive attachments so a maintainer can establish a private channel.

Please include the affected release/commit, deployment mode, impact, reproduction prerequisites, and the smallest safe reproduction that demonstrates the issue. Sanitized logs are preferred over raw captures.

## Security boundaries

Security invariants and threat analysis are maintained in `docs/threat-model.md`. The default management bind is loopback, cloud telemetry is opt-in/configured rather than required for local operation, and no web-facing process receives the Docker socket.

Pinned or otherwise interception-incompatible clients must fail or bypass only according to explicit policy; ShakerProxy must not silently weaken certificate validation on the client. DoH/DoT controls must not strand ordinary DNS resolution when policy or interception components fail.

## Releases and signing

Release signatures use the public trust root and fingerprint documented in `docs/release-process.md`. A valid signature proves release origin and integrity; it does not by itself establish production fitness.

Never report or attach a private signing key. A suspected signing-key compromise is release-blocking: stop publication, preserve workflow/repository audit evidence, revoke affected access, rotate the signing identity, and publish the replacement trust path through a reviewed source release.
