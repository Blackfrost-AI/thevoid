# Store, Website, and Object-Storage Handoff

## Scope of this handoff

The product repository now defines the artifact format, signing boundaries,
offline entitlement format, package installer, verification tools, and
fulfillment metadata. It has not connected to or changed the Blackfrost site,
store, DNS, cloud account, bucket, CDN, email provider, payment system, or
customer database.

The site/store agent should implement the integration described here using the
existing Blackfrost infrastructure. Do not copy cloud credentials or production
configuration into this repository.

## Delivery model

```text
protected source/tag
        |
        v
Kali release runner ---- signs once ----> generic release payload
        |                                      |
        |                                      v
        |                              private release prefix
        |
paid order event
        |
        v
isolated fulfillment worker -- issues license -- assembles one archive
        |                                      |
        v                                      v
 audit/order metadata                  private customer prefix
                                               |
                                               v
                                    short-lived authorized URL
                                               |
                                               v
                                      authenticated customer
```

The storefront never receives a signing private key in browser code. The web
process should enqueue an idempotent fulfillment request; an isolated worker
does the signing and archive work.

## Artifact contract

### Generic release input

Directory name:

```text
the-void-<version>-<architecture>/
```

Required files:

```text
RELEASE.json
README.txt
install.sh
SHA256SUMS
SHA256SUMS.sig
SBOM.core.spdx.json
SBOM.snowblind.spdx.json
packages/blackfrost-the-void_<version>-1_<architecture>.deb
packages/blackfrost-the-void-snowblind_<version>-1_<architecture>.deb
trust/license-public.pem
```

`RELEASE.json` includes `release_verifier_sha256`, the SHA-256 of the exact
external release public-key file used for verification.

Before accepting a release into fulfillment inventory, run:

```bash
python -m release.verify_release <release-dir> \
  --release-public-key <trusted-key-from-worker-configuration>
```

Run that module from a trusted worker deployment pinned to the reviewed product
tag; never execute a verifier copied out of the candidate archive. The trusted
key must come from protected worker configuration, not from the candidate
payload.

Publish the same public key through a stable, independently authenticated
Blackfrost site route (for example, a versioned trust-key endpoint), and show
its SHA-256 fingerprint in the customer portal. The release public key is not
included in the archive, and the installer rejects any key path located inside
the extracted download. A download cannot establish trust in a key carried
inside itself. Keep old public keys available for verifying previously released
versions, and record the active key ID with every release.

The GitHub release workflow transfers this directory as one
`*.generic.tar.zst` file with artifact re-archiving disabled. This preserves
the executable installer bit and avoids relying on workflow-artifact ZIP
permissions. Extract it into isolated worker staging, reject links and special
files, then run the verification command above before inventorying it.
Before extraction, reject absolute names, `..` path components, symlinks, hard
links, devices, FIFOs, and entries exceeding the configured size limit. Extract
into a new mode-`0700` directory with no overwrite behavior and destroy that
staging directory if any validation fails.

### Release workflow configuration

Create or update the protected GitHub environment named `commercial-release`.
Limit it to the release branch/tag policy and the dedicated Kali amd64 runner;
do not allow pull-request code from untrusted forks to access it. The manual
workflow expects these environment secrets:

| Secret | Value | Exposure |
|---|---|---|
| `VOID_LICENSE_PUBLIC_KEY_B64` | Base64 of the license public PEM | Public material, still configuration-controlled |
| `VOID_RELEASE_SIGNING_PUBLIC_KEY_B64` | Base64 of `release-signing.pub` | Public trust anchor |
| `VOID_RELEASE_SIGNING_PRIVATE_KEY_B64` | Base64 of the encrypted release private PEM | Release runner only |
| `VOID_RELEASE_SIGNING_KEY_PASSWORD` | Private-PEM passphrase | Release runner only |

Encode files without line wrapping, for example
`base64 -w 0 /secure/release-signing.pub`. Never paste decoded private material
into an issue, workflow file, job output, store configuration, or customer
record. The workflow removes its temporary private-key file in an `always()`
step; the self-hosted runner must also use isolated, ephemeral job directories
and an approved disk-cleanup policy.

The runner needs Python 3.13, `python3-venv`, Node/npm, `dpkg-deb`, GNU tar with
zstd support, OpenSSL, Syft, Trivy, Gitleaks, and access to the pinned Python/npm
dependencies during the build. The finished package itself embeds the Python
runtime dependencies and uses OpenSSL for offline release verification.

The workflow is deliberately manual and uploads only a short-retention private
Actions artifact. It does not write to the store or object storage. The
site/store integration should import that generic archive into quarantined
worker staging, verify it, then promote it to the private release prefix.

### Public trust-key route

Serve the exact `release-signing.pub` bytes from a stable HTTPS route such as
`/downloads/trust/the-void/<key-id>/release-signing.pub`. Store its SHA-256 in
trusted application configuration and display that value in the authenticated
portal next to each compatible release. The portal route must not select a key
name supplied by the browser without server-side allowlisting. Use an explicit
key ID on release records so rotation never changes the verifier for an already
published artifact.

### Per-order inputs

The worker needs:

- opaque customer ID;
- opaque order ID for idempotency/audit only;
- new opaque license ID;
- paid/approved order state;
- selected product version;
- entitlement features;
- `not_before` and optional expiry;
- the verified generic release path;
- access to the protected license signer;
- the independently trusted Ed25519 release public key.

Do not put customer names, email addresses, company names, engagement names,
real targets, credentials, rules of engagement, or assessment data into a
license or filename.

### Per-order outputs

`assemble_customer_bundle` writes:

```text
the-void-<version>-linux-<architecture>-<token>.tar.zst
the-void-<version>-linux-<architecture>-<token>.sha256
the-void-<version>-linux-<architecture>-<token>.metadata.json
```

The metadata JSON is the machine contract for the store worker. Persist at
least its archive name, bytes, SHA-256, version, architecture, customer ID,
license ID, expiry, source commit, storage key, fulfillment state, and creation
time. The short filename token is derived from the license ID and is not the
customer ID.

## Suggested private object-key layout

Use the existing bucket and naming conventions if they are stricter. A clean
logical layout is:

```text
commercial/the-void/releases/<version>/linux/amd64/<generic-file>
commercial/the-void/customers/<opaque-customer-id>/<opaque-license-id>/<archive>
commercial/the-void/customers/<opaque-customer-id>/<opaque-license-id>/<archive>.sha256
```

Keep the bucket private with Block Public Access enabled. Use the organization's
approved server-side encryption key, versioning, access/audit logging, and
lifecycle policies. Consider retention lock only if it matches legal and
support policy; it can prevent emergency deletion. Separate temporary worker
files from retained release objects and expire failed/abandoned fulfillment
staging quickly.

No object should be made anonymously public. A “download” button should call an
authenticated backend endpoint that verifies ownership and order state, records
the attempt, and returns a short-lived signed URL. Do not create presigned URLs
in frontend JavaScript and never expose cloud access keys to the browser.

## Fulfillment state machine

Use an idempotency key derived from the store/order event ID. Recommended states:

```text
pending -> entitled -> assembled -> verified -> uploaded -> available
   |           |           |           |           |
   +---------- failed (retryable or terminal with recorded reason) --------+
```

Required worker sequence:

1. Authenticate the store webhook or consume the trusted internal order event.
2. Confirm payment/approval and product/version selection server-side.
3. Acquire an idempotency lock; return the prior result for a completed order.
4. Verify the generic release with the pinned release key.
5. Generate opaque customer/license IDs if they do not already exist.
6. Issue the Ed25519 entitlement in the isolated signing context.
7. Assemble the archive with `release.assemble_customer_bundle`.
8. Verify the archive sidecar digest and extract/verify a sample according to policy.
9. Upload with explicit content type and encryption settings.
10. Read object metadata back and compare size/checksum.
11. Persist the immutable object version/key and transition to `available`.
12. Notify the customer without attaching the license or archive to email.
13. Destroy worker plaintext staging under the approved ephemeral-data policy.

Never mark an order available before upload verification succeeds. A retry must
not issue multiple active licenses unless business policy explicitly requests a
replacement.

## Website/API contract

Adapt endpoint names to the existing application. The backend behavior should
support these concepts:

### List downloads

```json
{
  "product": "the-void",
  "downloads": [
    {
      "version": "1.1.0",
      "platform": "linux",
      "architecture": "amd64",
      "license_id": "opaque-license-id",
      "expires_at": "RFC3339-or-null",
      "bytes": 123456,
      "sha256": "64-lowercase-hex",
      "status": "available"
    }
  ]
}
```

### Request a download URL

Input is the authenticated download/license record ID—not an arbitrary object
key. The server must:

1. authorize the logged-in account against the order;
2. ensure the entitlement/download remains available;
3. resolve the stored object key server-side;
4. create a short-lived URL (for example, 10–15 minutes);
5. force attachment disposition with the canonical filename;
6. return the SHA-256 value and expiry alongside the URL;
7. record customer/account, order, object version, IP/user agent according to
   privacy policy, and request/result timestamps.

Rate-limit URL issuance and avoid including object keys, bucket names, internal
errors, credentials, or signing details in client-visible failures.

## Portal copy

The product/download page should make these points clear:

- Kali Linux amd64 is the supported commercial target for this release.
- The download is customer-specific and governed by the purchased license.
- The Command Center is local and browser-first; no hosted control plane or
  telemetry is required.
- The archive contains THE VOID and the Snowblind companion—there is no second
  product download.
- Show filename, version, size, SHA-256, license expiry, release notes, and
  supported upgrade path.
- Publish the pinned release-key fingerprint through the authenticated portal.
- Give concise extract/install/launch commands and a link to customer support.
- Tell customers to retain recovery access and run `sudo snowblind doctor`
  before any privileged Snowblind operation.

Do not claim that compilation makes the application impossible to inspect or
that a private repository alone guarantees product security.

## Content types and headers

Recommended object metadata:

| File | Content type | Disposition |
|---|---|---|
| `.tar.zst` | `application/zstd` | attachment; canonical archive filename |
| `.sha256` | `text/plain; charset=utf-8` | attachment |
| `.json` internal metadata | `application/json` | never customer-public unless explicitly sanitized |

For customer responses, use `Cache-Control: private, no-store` on URL-issuing
API responses. The immutable binary object may use a long cache lifetime only
behind authorization-aware delivery and with a content-addressed/versioned key.

## Failure, replacement, and revocation

- Payment reversal or account suspension should block new URL issuance.
- Because entitlement verification is offline, removing the object does not
  deactivate an already installed license. Use expiry/renewal policy for that
  requirement or design a separately approved online revocation feature later.
- A replacement license should have a new license ID and an audit link to the
  superseded ID. Never overwrite the old object in place.
- A bad release should be disabled in fulfillment inventory, not silently
  replaced at the same key. Preserve the affected commit/hash for incident
  analysis according to policy.
- Customer support bundles must be sanitized; they should not contain the
  customer's license file unless the secure support process explicitly needs it.

## Acceptance checklist for the site/store agent

- [ ] Existing store entitlement/order model mapped to opaque customer and license IDs.
- [ ] Fulfillment worker is separate from browser/frontend execution.
- [ ] Signing material is absent from repository, frontend, logs, artifacts, and email.
- [ ] Generic release is verified with an out-of-band pinned Ed25519 public key.
- [ ] Paid-order webhook/event is authenticated and idempotent.
- [ ] Customer archive is assembled and checksum metadata persisted.
- [ ] Bucket/prefix remains private and encrypted; public access is blocked.
- [ ] Upload is verified before the order becomes downloadable.
- [ ] Download endpoint enforces account ownership and returns a short-lived URL.
- [ ] Portal displays version, platform, size, SHA-256, expiry, and install instructions.
- [ ] Release-key fingerprint is shown from trusted site configuration.
- [ ] Failed staging data and expired URLs are cleaned up without deleting retained releases.
- [ ] Development/dirty/unsigned payloads are rejected from production fulfillment.
- [ ] End-to-end test covers paid order, retry, unauthorized account, expired URL,
      replaced license, disabled release, checksum mismatch, and successful Kali install.
