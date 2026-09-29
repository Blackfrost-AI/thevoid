"""THE VOID — Crypto: The encryption engine for all communications.

AES-256-GCM, HMAC, key derivation, and key rotation.
Key material is never logged or exposed via repr.
"""

import os
import base64
import hashlib
import hmac
import secrets
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("void.crypto")

# OWASP 2023 recommendation for PBKDF2-HMAC-SHA256 is ≥600_000 iterations.
PBKDF2_ITERATIONS = 600_000


class Crypto:
    """Encryption engine for THE VOID."""

    def __init__(self, key: Optional[bytes] = None):
        """Initialize the crypto engine.

        Args:
            key: 256-bit key (32 bytes). If None, generates a new key.
        """
        if key is None:
            key = secrets.token_bytes(32)
        if len(key) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes")
        self._key = key
        logger.info("Crypto initialized (AES-256-GCM, key material not logged)")

    @property
    def key(self) -> bytes:
        return self._key

    def derive_key(self, passphrase: str, salt: Optional[bytes] = None) -> bytes:
        """Derive a key from a passphrase using PBKDF2-HMAC-SHA256.

        Args:
            passphrase: The passphrase to derive the key from
            salt: Salt for the derivation (if None, generates random)

        Returns:
            32-byte derived key
        """
        if salt is None:
            salt = os.urandom(16)
        return hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode(), salt, PBKDF2_ITERATIONS, dklen=32
        )

    def encrypt_aes(self, plaintext: str) -> Dict[str, str]:
        """Encrypt text using AES-256-GCM.

        Args:
            plaintext: Text to encrypt

        Returns:
            Dict with 'ciphertext' and 'nonce' (base64-encoded)
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)
        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        }

    def decrypt_aes(self, ciphertext: str, nonce: str) -> str:
        """Decrypt text using AES-256-GCM.

        Args:
            ciphertext: Base64-encoded ciphertext
            nonce: Base64-encoded nonce

        Returns:
            Decrypted text
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        ct_bytes = base64.b64decode(ciphertext)
        nonce_bytes = base64.b64decode(nonce)
        aesgcm = AESGCM(self._key)
        plaintext = aesgcm.decrypt(nonce_bytes, ct_bytes, None)
        return plaintext.decode("utf-8")

    def encrypt_json(self, data: Dict[str, Any]) -> str:
        """Encrypt a JSON-serializable object.

        Args:
            data: The data to encrypt

        Returns:
            Base64-encoded encrypted string
        """
        import json

        plaintext = json.dumps(data, default=str)
        encrypted = self.encrypt_aes(plaintext)
        return base64.b64encode(json.dumps(encrypted).encode()).decode()

    def decrypt_json(self, encrypted_str: str) -> Dict[str, Any]:
        """Decrypt a JSON-serializable object.

        Args:
            encrypted_str: Base64-encoded encrypted string

        Returns:
            Decrypted data
        """
        import json

        encrypted = json.loads(base64.b64decode(encrypted_str))
        plaintext = self.decrypt_aes(encrypted["ciphertext"], encrypted["nonce"])
        return json.loads(plaintext)

    def hmac_sign(self, message: str) -> str:
        """Create an HMAC-SHA256 signature for a message."""
        return hmac.new(self._key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def hmac_verify(self, message: str, signature: str) -> bool:
        """Verify an HMAC signature (constant-time compare)."""
        expected = hmac.new(
            self._key, message.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def generate_key_exchange(self) -> Dict[str, str]:
        """Generate an ECDH P-256 key pair for real key agreement.

        Returns:
            Dict with base64-encoded 'public_key' (X962 uncompressed) and
            'private_key' (32-byte scalar). Use :meth:`derive_shared_secret`
            with the peer public key to obtain a shared secret.
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        priv_bytes = private_key.private_numbers().private_value.to_bytes(32, "big")
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return {
            "public_key": base64.b64encode(pub_bytes).decode(),
            "private_key": base64.b64encode(priv_bytes).decode(),
            "curve": "SECP256R1",
        }

    def derive_shared_secret(
        self, private_key_b64: str, peer_public_key_b64: str
    ) -> bytes:
        """Derive an ECDH shared secret from local private + peer public key."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        priv_bytes = base64.b64decode(private_key_b64)
        pub_bytes = base64.b64decode(peer_public_key_b64)
        private_key = ec.derive_private_key(
            int.from_bytes(priv_bytes, "big"), ec.SECP256R1()
        )
        peer_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), pub_bytes
        )
        return private_key.exchange(ec.ECDH(), peer_public)

    def rotate_key(self) -> bytes:
        """Rotate the encryption key. Key material is not logged."""
        self._key = secrets.token_bytes(32)
        logger.info("Encryption key rotated (key material not logged)")
        return self._key

    def advance_key(self, info: bytes) -> bytes:
        """Derive the next key deterministically from the current key.

        Both peers holding the same key and calling with the same ``info``
        end up on the same new key (session re-keying); the old key is
        discarded. Key material is never logged.
        """
        import hashlib
        import hmac as _hmac

        self._key = _hmac.new(self._key, b"void-rekey" + info, hashlib.sha256).digest()
        return self._key

    # ─── String compat API ──────────────────────────────────────────────────

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string to a base64 transport blob.

        String-level counterpart of :meth:`encrypt_json` for wire protocols
        (C2 daemon/beacon/commands) that carry opaque string payloads.
        """
        import json

        encrypted = self.encrypt_aes(plaintext)
        return base64.b64encode(json.dumps(encrypted).encode()).decode()

    def decrypt(self, blob: str) -> str:
        """Decrypt a blob produced by :meth:`encrypt` back to a string."""
        import json

        encrypted = json.loads(base64.b64decode(blob))
        return self.decrypt_aes(encrypted["ciphertext"], encrypted["nonce"])

    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Dict[str, str]:
        """Hash a password using PBKDF2-HMAC-SHA256 (600k iterations)."""
        if salt is None:
            salt = os.urandom(16)
        pw_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, PBKDF2_ITERATIONS, dklen=32
        )
        return {
            "hash": base64.b64encode(pw_hash).decode(),
            "salt": base64.b64encode(salt).decode(),
            "iterations": PBKDF2_ITERATIONS,
        }

    def verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """Verify a password against its hash."""
        salt_bytes = base64.b64decode(salt)
        pw_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt_bytes, PBKDF2_ITERATIONS, dklen=32
        )
        return hmac.compare_digest(base64.b64encode(pw_hash).decode(), password_hash)

    def __repr__(self) -> str:
        return "Crypto(algorithm=AES-256-GCM)"
