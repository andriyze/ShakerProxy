# Mitmproxy namespace proof

Run the isolated proof with:

```bash
make netlab-mitmproxy
```

The runner builds from the official mitmproxy 12.2.3 multi-architecture image
at manifest digest
`sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f`.
Its small set of native test tools comes from the immutable Debian snapshot
recorded by that upstream image. Docker drops its default capability set and
grants only the namespace, interface, low-port fixture, temporary ownership,
privilege-drop, and cleanup capabilities required by the harness. It does not
use host networking or `--privileged`.

Inside that disposable container, `mitmproxy-proof.sh` creates client, gateway,
and origin network namespaces joined only by uniquely named veth pairs. The
container's original default-route hash is checked again during cleanup. The
proxy child runs as UID/GID 65532 with no supplementary groups, an empty
capability bounding set, and `no_new_privs`.

The proof loads the exact shipped `apps/mitmproxy/shakerproxy_addon.py` and its
compiled product policy format. It asserts all of the following:

- an explicit-proxy client without the generated public CA rejects the TLS
  interception;
- the same explicit request succeeds after the client trusts that CA;
- an exact client/origin/TCP-443 owned `REDIRECT` rule succeeds in transparent
  mode;
- TCP 8443 remains outside the redirect and validates directly against the
  independent origin CA;
- mitmproxy validates upstream TLS against the configured origin trust root and
  rejects a server signed by a different root;
- the stream file is non-empty and owned by the non-root proxy identity;
- the product addon emits non-root-owned `tls_intercepted`, `http_request`, and
  `http_response` envelopes, and those payloads contain metadata rather than
  request or response bodies.

The installed-host feature separately includes a digest-pinned Compose service,
service-private interception CA provisioner, authenticated public-CA download,
revisioned local and cloud-managed policy paths, bounded metadata forwarding, selective
device and manual bypass rules, pinning-aware automatic bypass, and local
emergency fail-open reconciliation. A root-owned cross-process lock plus explicit
cloud-connector ownership handoff prevents the local reconciler from replacing an
active cloud-managed proxy snapshot. Unit, API, and Compose security tests cover those
boundaries. Local ingestion also verifies bounded endpoint/TLS outcome
projection, canonical device identity delivery, UI trust-path aggregation, and
conservative probable-pinning explanations. The namespace proof is still not physical-device or packaged
clean-host certification; Android, iOS, Smart TV, desktop, reboot, revocation,
pinning, and sustained-load matrices remain promotion gates.
