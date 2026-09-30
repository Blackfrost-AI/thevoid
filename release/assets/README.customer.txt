THE VOID — CUSTOMER INSTALL BUNDLE
==================================

This bundle contains the signed Kali packages, a customer-specific offline
license, dependency inventories, and integrity metadata.

Prerequisites are Kali Linux amd64 with Python 3.13, OpenSSL, and configured Kali
package sources for any missing Snowblind system dependencies. Python
application dependencies are embedded, while Python 3.13 is a declared system
dependency. The entitlement remains fully offline after installation.

Download the Blackfrost release-verification public key separately from the
authenticated customer portal. Keep it outside this extracted directory, then
install on the licensed Kali workstation:

  sudo ./install.sh /path/to/blackfrost-release-signing.pub

Then open THE VOID Command Center from the application menu or run:

  thevoid-command-center start

The Command Center binds only to localhost. Snowblind is installed as a
separate least-privilege companion and performs no network or host changes at
package-install time. Review its acceptable-use document and run
`sudo snowblind doctor` before an authorized session.

Before installation, compare that key's fingerprint and the archive SHA-256
with the values published through the authenticated Blackfrost customer
portal. The installer deliberately refuses a key carried inside this bundle.
See docs/OPERATOR_GUIDE.md and the root README for release and
verification procedures.
