# Suricata ruleset maintenance

ShakerProxy currently ships one deliberately narrow first-party cleartext-service
policy. It is not an Emerging Threats mirror, a threat-intelligence feed, or a
claim of comprehensive intrusion detection. A signed offline lifecycle now
validates, previews, pins, versions, and rolls back replacement content; an
unattended network source is not enabled.

The rules and `suricata-ruleset.json` provenance manifest are one immutable
release artifact. The manifest binds the policy ID and version, source and
license, supported Suricata version, exact SHA-256, active rule count, and the
complete reserved SID interval. The analyzer refuses to run Suricata when the
files drift, contain an unsupported active line, reuse a SID, or disagree with
the declared inventory.

## Maintainer update procedure

1. Edit `apps/analyzer-worker/suricata.rules`. Keep first-party SIDs unique and
   inside the manifest's reserved interval. Document false-positive and privacy
   consequences in the rule message or change review.
2. Advance the calendar-based ruleset version and `updated_at`. Update the rule
   count and exact minimum/maximum SID values.
3. Compute the SHA-256 over the rules file bytes and place it in the manifest.
   Do not regenerate the digest merely to silence unexplained drift.
4. Run `make verify`. The repository test validates the digest, manifest schema,
   active-line inventory, and unique SIDs.
5. Build `apps/analyzer-worker/Dockerfile.suricata`. Image construction must pass
   Suricata 8.0.6 native configuration/rule validation before publication.
6. Review the rules, provenance manifest, test evidence, and license record in
   the same commit. Publish only through the normal immutable-image release
   process.

The image-bound rules remain the startup fallback. The common signed-content
lifecycle in `docs/signed-content.md` can stage a replacement and preserves a
verified last-known-good revision. Until the Compose consumer reload boundary
is wired and clean-VM tested, CLI updates report `VALIDATED_PENDING_RELOAD` and
must not be described as active or healthy. Any external feed must still add
license review, an explicit egress source, and signed release metadata before it
can replace this offline contract.
