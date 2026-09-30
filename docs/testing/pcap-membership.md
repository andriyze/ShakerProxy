# PCAP membership evidence

Run the focused parser, manifest, and consumer checks with the pinned toolchain:

```bash
docker run --rm -v "$PWD:/src" -w /src \
  golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee \
  go test ./internal/pcapng ./internal/capture ./internal/analyzer
```

The fixtures cover little- and big-endian sections, multiple interfaces,
Ethernet, stacked VLAN headers, raw IPv4, IPv6, sorted canonical identities,
unsupported link types, truncated packet headers, malformed block lengths, and
arbitrary fuzz inputs. Store tests prove membership and artifact SHA-256 are
computed over the same opened byte stream and persisted together in the final
manifest. Host deletion and analyzer intake reject malformed optional
membership evidence while accepting legacy manifests that predate the field.

Only `EXACT` means every packet block was structurally valid, used a supported
link type, exposed sufficient identity headers, and stayed within the bounded
identity population. All other states are limitations, not estimates.
