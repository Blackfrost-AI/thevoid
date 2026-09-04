# Private Commercial Distribution

> **Release hold:** this document describes the intended delivery architecture,
> not a commissioned release. The installer still needs transactional entitlement
> validation and clean-Kali lifecycle acceptance. A monitored `VOID_SUPPORT_EMAIL`
> and named release reviewer must be confirmed. See [HARDENING_HANDOFF.md](HARDENING_HANDOFF.md).

## Decision

Ship THE VOID as one customer-specific `tar.zst` download containing two
native Kali/Debian packages:

| Package | Responsibility | Privilege model |
|---|---|---|
| `blackfrost-the-void` | Frosty, the CLI, Command Center backend/frontend, evidence stores, reports, and the bundled MCP scanner | Runs as the desktop operator |
| `blackfrost-the-void-snowblind` | Snowblind host/network companion | Invoked explicitly with `sudo` only when required |

The generic packages are built and signed once per release. The store adds one
customer's independently signed offline license and creates the final archive;
it does not rebuild application code for each order.

Keep the source repository private. A wheel, `.deb`, archive, or frozen Python
executable is a delivery format—not a confidentiality boundary. Customers who
can execute Python software can inspect it. Bun's executable compiler targets
JavaScript/TypeScript, not this Python/FastAPI application. Freezing the backend
would add platform and subprocess complexity without preventing determined
inspection. Commercial protection should come from access control, licensing,
contracts, release signing, watermark-free audit records, and support—not a
claim that packaged code is secret.

## Customer experience

The customer downloads one archive and the release-verification public key over
independent authenticated portal routes, compares the archive SHA-256 and key
fingerprint with the displayed values, extracts the archive, and runs:

```bash
sudo ./install.sh /path/to/blackfrost-release-signing.pub
```

The key must remain outside the extracted download. The installer deliberately
refuses any key located inside the bundle, verifies the signed checksum manifest
before hashing payload files, installs both local packages through APT, places
the signed entitlement at `/etc/blackfrost/the-void/license.json`, and verifies
it locally. Blackfrost package scripts do not start THE VOID or change active
firewall/routing policy; normal Kali dependency-package policy still applies.
The customer machine needs OpenSSL and configured Kali package sources if any
declared Snowblind system dependency is not already present. Python application
dependencies are embedded in the core package; the entitlement check itself is
offline and requires no licensing service.

After installation, the customer opens **THE VOID Command Center** from Kali's
application menu or runs:

```bash
thevoid-command-center start
```

Useful lifecycle commands:

```bash
thevoid-command-center status
thevoid-command-center open
thevoid-command-center stop
thevoid license status
```

The visual console always binds to loopback. Its PID record is private to the
operator, and the stop command checks both process ownership and command line
before sending `SIGTERM`.

## Runtime and install layout

Read-only application files:

```text
/opt/blackfrost/the-void/app/
/opt/blackfrost/the-void/venv/
/usr/bin/thevoid
/usr/bin/thevoid-command-center
/usr/bin/snowblind
/usr/share/applications/blackfrost-the-void.desktop
/usr/share/blackfrost/the-void/license-public.pem
```

Entitlement:

```text
/etc/blackfrost/the-void/license.json
```

Per-operator mutable data follows XDG:

```text
~/.config/blackfrost/the-void/
~/.local/state/blackfrost/the-void/
~/.local/share/blackfrost/the-void/
~/.cache/blackfrost/the-void/
```

Snowblind's privileged journal and recovery state defaults to:

```text
/var/lib/blackfrost/the-void/snowblind/
```

The `VOID_CONFIG_DIR`, `VOID_STATE_DIR`, `VOID_DATA_DIR`, `VOID_CACHE_DIR`, and
`VOID_RUNTIME_DIR` environment variables provide explicit suite-wide
overrides. `SNOW_STATE_DIR` overrides Snowblind's state root. No migration of
old engagement data is automatic; copy only intentionally reviewed data.

## Trust anchors and key separation

Use different keys for different jobs:

| Key | Purpose | Where private material belongs |
|---|---|---|
| License Ed25519 key | Signs customer/product/feature/expiry payloads | Isolated fulfillment signer or protected secret service |
| Release Ed25519 key | Signs the generic `SHA256SUMS` | Protected release runner or isolated signing context |

Only the license verification public key enters release payloads. The release
verification public key remains an independently delivered trust anchor. Never
commit either private key, a passphrase, production license, customer
identifier, or generated bundle. Publish the release-key fingerprint in the
authenticated customer portal so a customer does not have to trust a key
delivered inside the same archive it verifies.

The current entitlement is offline by design. That preserves local-only
operation, but it also means immediate remote revocation is impossible. Stop
future downloads in the store and use appropriately short expirations with
renewal when revocation speed matters.

## One-time release preparation

Use a controlled Kali amd64 builder matching the customer target. The builder
needs Python, `python3-venv`, Node/npm, `dpkg-deb`, `zstd`, Syft, OpenSSL, and the
normal test/security toolchain.

Generate the license key outside the repository. The passphrase is read only
from the environment:

```bash
export VOID_LICENSE_KEY_PASSPHRASE='retrieve from the approved secret manager'
python -m release.license_tool keygen \
  --private-key /secure/license-signing.pem \
  --public-key /secure/license-public.pem
unset VOID_LICENSE_KEY_PASSPHRASE
```

The utility refuses an unencrypted key unless `--unencrypted` is explicitly
chosen. That flag is for ephemeral test keys, not production. It also preflights
both output paths before generating anything. Never use `--force` to rotate a
production signer: create a new key ID/path, retain the old public key for old
releases and licenses, and follow the approved rotation procedure.

Generate a separate encrypted Ed25519 release key outside the repository. Keep
its passphrase in the approved secret manager, never on the command line:

```bash
export VOID_RELEASE_SIGNING_KEY_PASSWORD='retrieve from the approved secret manager'
umask 077
openssl genpkey -algorithm ED25519 -aes-256-cbc \
  -pass env:VOID_RELEASE_SIGNING_KEY_PASSWORD \
  -out /secure/release-signing.key
openssl pkey -in /secure/release-signing.key \
  -passin env:VOID_RELEASE_SIGNING_KEY_PASSWORD \
  -pubout -out /secure/release-signing.pub
chmod 0600 /secure/release-signing.key
chmod 0644 /secure/release-signing.pub
unset VOID_RELEASE_SIGNING_KEY_PASSWORD
```

Publish the exact public-key file separately from product archives. Its portal
fingerprint is `sha256sum /secure/release-signing.pub`; `RELEASE.json` records
that same exact-file digest.

Create the offline wheelhouse on the intended builder:

```bash
python -m release.prepare_wheelhouse
```

`requirements-runtime.txt` locks every direct and transitive dependency to a
version and approved wheel SHA-256 for Python 3.13 on Linux amd64. The generated
`wheelhouse-manifest.json` independently binds the downloaded wheel set to
those requirements, the Python version, architecture, and platform. Both
download and install use pip's `--require-hashes`, and package installation
also uses `--no-index`; a release cannot silently fetch or substitute a new
dependency.

## Build a production release

The production build refuses a dirty worktree, an architecture other than
`amd64`, a mismatched app version, a changed wheelhouse, an uncommitted
frontend build, missing SBOM tooling, missing license public key, or missing
release-signing inputs.

```bash
git status --short
python -m pytest tests commandcenter/tests/backend -q --timeout=600

export VOID_RELEASE_SIGNING_KEY_PASSWORD='retrieve from the approved secret manager'
python -m release.build_release \
  --license-public-key /secure/license-public.pem \
  --release-signing-key /secure/release-signing.key \
  --release-public-key /secure/release-signing.pub
unset VOID_RELEASE_SIGNING_KEY_PASSWORD
```

The command produces `release/out/the-void-<version>-amd64/` containing:

- both `.deb` packages;
- SPDX JSON SBOMs for both package trees;
- `RELEASE.json` with commit, version, platform, and build epoch;
- the customer installer and customer README;
- the license verification public key;
- `SHA256SUMS` plus its detached Ed25519 signature, `SHA256SUMS.sig`.

The release public key is intentionally not copied into the payload. The
current build command accepts an encrypted local PEM key; keep it only in the
protected release environment and supply its password through the named
environment variable so it never appears in command history or process
arguments.

Verify using the public key obtained outside the payload:

```bash
python -m release.verify_release \
  release/out/the-void-1.1.0-amd64 \
  --release-public-key /secure/release-signing.pub
```

## Fulfill one order

Use opaque store IDs, not a person's name, company name, email, target, or
engagement identifier:

```bash
export VOID_LICENSE_KEY_PASSPHRASE='retrieve from the approved secret manager'
python -m release.license_tool issue \
  --private-key /secure/license-signing.pem \
  --customer-id cust_opaque_123 \
  --license-id lic_opaque_456 \
  --product-version 1.1.0 \
  --days 365 \
  --output /secure/fulfillment/lic_opaque_456.json
unset VOID_LICENSE_KEY_PASSPHRASE

python -m release.assemble_customer_bundle \
  --release-dir release/out/the-void-1.1.0-amd64 \
  --license /secure/fulfillment/lic_opaque_456.json \
  --release-public-key /secure/release-signing.pub \
  --output /secure/fulfillment/out
```

The archive name uses a one-way short token derived from the license ID. The
sidecar metadata is for the fulfillment service and includes the opaque
customer/license IDs, archive size, and SHA-256 value. Neither file belongs in
Git.

The assembler verifies the generic release signature with the independently
supplied public key, verifies the customer's Ed25519 license, checks its
version and required features, and refuses unsigned/development releases.

## Development-only package smoke test

Development mode is visibly marked and disables entitlement enforcement. It
exists only to exercise packaging on a working tree:

```bash
python -m release.build_release \
  --development --allow-dirty --skip-frontend

python -m release.verify_release \
  release/out/the-void-1.1.0-amd64 \
  --development
```

Never upload a development payload to customer-facing storage. The production
assembler rejects it unless its own explicit `--development` test flag is used.

## Release gate

Before uploading a generic release:

1. Confirm `git status --short` is empty and HEAD is the intended protected tag.
2. Run the complete Python and frontend suites.
3. Run fatal lint plus full dependency and secret scans.
4. Prepare and verify the exact wheelhouse on Kali amd64.
5. Build both packages and both SBOMs.
6. Verify `SHA256SUMS` with the external Ed25519 release public key.
7. Inspect package metadata and file lists without installing.
8. Install a test entitlement on a disposable Kali VM and run browser/CLI smoke tests.
9. Confirm uninstall/reinstall preserves intended operator state and removes package-owned files.
10. Upload only the verified release payload—not the worktree, keys, caches, test DBs, or logs.

## Upgrade and recovery behavior

- Installing a newer package replaces package-owned application files but does
  not remove XDG evidence or the installed customer license.
- Stop the Command Center before upgrading, then restart it explicitly.
- Snowblind must be restored to baseline before its package is upgraded or
  removed. Never delete its journal while host changes remain active.
- Package rollback requires an explicitly retained and still trusted older
  release. A license must permit that product version.
- Uninstalling packages does not imply deletion of customer evidence. Data
  removal is a separate, deliberate retention-policy action.

## Reference material

- Debian package installation and inspection: <https://www.debian.org/doc/manuals/debian-handbook/sect.manipulating-packages-with-dpkg.en.html>
- Python wheel format: <https://packaging.python.org/en/latest/specifications/binary-distribution-format/>
- OpenSSL `pkeyutl`: <https://docs.openssl.org/3.3/man1/openssl-pkeyutl/>
- Bun compiled executables: <https://bun.sh/docs/bundler/executables>
- PyInstaller operating model: <https://pyinstaller.org/en/stable/operating-mode.html>
