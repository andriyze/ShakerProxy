# Management TLS and authority separation

Production ShakerProxy management traffic terminates at Caddy on HTTPS port 8443.
The certificate is signed by a local, purpose-constrained **management CA**.
That authority is not, and must never become, the TLS interception authority.
Development remains loopback-only HTTP so local fixtures do not create ambient
trust or imply production enrollment.

## Trust boundary

The Debian post-install step creates this layout:

```text
/etc/shakerproxy/pki/
  management/
    root-ca.key                 root:root 0400
    root-ca.crt                 root:root 0444
    status.json                 public metadata, 0444
    current -> leaf-<UTC time>
    leaf-<UTC time>/
      tls.key                   root:shakerproxy-edge 0440
      tls.crt                   root:root 0444
  interception/
    purpose.json                root:root 0600; reserved separation marker

/var/lib/shakerproxy/mitmproxy/
  mitmproxy-ca.pem              service-private interception CA bundle, 0400
  mitmproxy-ca-cert.pem         public certificate for mitmproxy, 0444

/var/lib/shakerproxy/public/
  management-ca.crt             public certificate only, 0644
  management-pki.json           fingerprint and validity only, 0644
  interception-ca.pem           public interception certificate only, 0444
  interception-ca.der           public interception certificate only, 0444
  interception-ca.json          fingerprint and validity only, 0444
```

The management root uses ECDSA P-256, `CA=true`, and only certificate/CRL-sign
key usage. The leaf uses only server authentication and cannot sign
certificates. Its default names are `shakerproxy.local`, `localhost`, `127.0.0.1`,
and `::1`. A leaf is rotated atomically when it has fewer than 30 days left.
Invalid, incomplete, mismatched, expired, or purpose-confused existing material
causes provisioning to fail; it is never silently replaced.

The edge container receives only the current leaf certificate and private key.
It receives neither the management root private key nor any interception path.
The control API receives only the public management certificate and metadata.
The reserved management-PKI interception namespace remains keyless and exists
only to reject management-authority reuse. The actual RSA interception authority
is independently provisioned in the fixed-identity mitmproxy data directory.
Only the non-root mitmproxy identity and root can read its private bundle. The
control API receives only public interception projections. Neither authority's
private key leaves the appliance.

## Enrollment and inspection

An authenticated administrator can inspect metadata at
`GET /api/v1/system/management-pki` and download the public certificate at
`GET /api/v1/system/management-ca.pem`. Both responses are `no-store`; the PEM
response is explicitly labeled `shakerproxy-management-tls`. Download means only
that the certificate was served—it does not mean a client trusted it.

On the appliance, the equivalent fixed-path commands are:

```text
shakerproxy management-ca status
shakerproxy management-ca export ./shakerproxy-management-ca.crt
```

Export refuses to overwrite a destination. Administrators must compare the
SHA-256 fingerprint over a separately authenticated channel before enrolling
the certificate. Never install this certificate as an interception CA, never
copy its private key, and never distribute it as part of an application
profile that grants content-decryption trust.

The separate interception authority is available to an authenticated
administrator at `GET /api/v1/interception-ca`; its public certificate can be
downloaded as PEM or DER at `GET /api/v1/interception-ca/download`. The local
dashboard guides the operator through fingerprint verification, authorized
test-device enrollment, gateway/DNS setup, and an HTTPS trial. It then groups
the newest bounded MITM outcomes by canonical device ID, falling back to client
IP when no device identity exists.

`INTERCEPTED` proves that one client connection accepted the generated ShakerProxy
leaf. `FAILED` without recent successful interception remains ambiguous between
missing CA trust and application pinning. ShakerProxy labels probable pinning only
after repeated failure on a declared mobile client with recent successful
interception; if configured, it also reports that a temporary scoped bypass was
activated. None of these observations claims OS-wide trust or support for every
app, and no request body, response body, credential, raw certificate, or private
key is projected into this view.

## Recovery and limitations

The management root private key is appliance state and must be included in an
encrypted, access-controlled appliance backup. Restoring a different root
changes the fingerprint and requires explicit client re-enrollment. Losing the
root does not justify silently generating a replacement during repair.

This slice is `experimental`. It has deterministic implementation tests and a
production Compose boundary, but browser enrollment, leaf rotation under the
running edge, encrypted backup/restore, and clean Ubuntu 24.04/26.04 lifecycle
evidence are still promotion gates. TLS interception is separately experimental,
disabled by default, and not certified on physical client platforms.
