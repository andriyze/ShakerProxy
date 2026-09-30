# Signed rules and catalog lifecycle

Rulesets and intelligence catalogs are executable policy inputs, so ShakerProxy
does not treat a successful download as an update. A common bounded lifecycle
accepts three content kinds: Suricata rules plus provenance, a Zeek package lock,
and a resolver catalog. Network fetching is deliberately outside this trusted
core; online and offline delivery produce the same signed bundle.

Every bundle carries the exact manifest bytes, an RSA-3072/SHA-256 signature,
and an allowlisted artifact map. The manifest binds content kind, calendar
revision, name, source, creation time, signing-key fingerprint, filenames,
sizes, and SHA-256 values. Verification rejects unknown fields, extra or missing
files, traversal-capable filenames, wrong keys, modified signatures, content
drift, malformed Suricata provenance/rules, malformed Zeek locks, and malformed
resolver catalogs before active state changes.

`shakerproxy rules preview <bundle.json>` verifies the signature and returns an
artifact-level added/removed/changed/unchanged diff. `update` applies against
the current optimistic revision under the appliance configuration lock. `pin`
blocks any different revision; `pin ... none` removes the pin. `rollback`
selects the verified prior revision without a network fetch. `status` exposes
current, previous, pinned, last result, failure, and a SHA-256-chained audit.

```text
sudo shakerproxy rules preview update.json
sudo shakerproxy rules update update.json
sudo shakerproxy rules pin suricata 2026.09.02.4
sudo shakerproxy rules pin suricata none
sudo shakerproxy rules rollback suricata
shakerproxy rules status
```

The manager has a post-activation consumer-health boundary. A failed health
callback atomically restores the prior state, reloads the prior object, and
records `AUTO_ROLLED_BACK`. A manual rollback whose target fails health restores
the original revision too. This behavior is covered with real signatures and
valid Suricata fixtures.

The packaged CLI currently performs signature and native structural validation
and stores revisions, but it does not yet restart the Compose consumer. It
therefore reports `VALIDATED_PENDING_RELOAD`, never `HEALTHY`. Clean-VM engine
reload, `suricata -T`, Zeek lock enforcement, update-source egress, and abrupt
power-loss tests remain promotion gates. IDS rules are observational; this does
not add an inline IPS.
