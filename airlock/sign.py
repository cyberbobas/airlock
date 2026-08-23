"""Signing for the audit chain (plane 5).

The hash chain proves the file was not edited in place. It does not prove who
wrote it — anyone who can append can extend the chain. Signing closes that gap,
to the extent the key is out of the attacker's reach:

  hmac      (default when enabled) a symmetric key in $AIRLOCK_HOME/audit.key,
            0600. Detects tampering by anything that cannot read that file —
            which includes a shipped-off copy of the log, but NOT a process
            running as the same user. Cheap and dependency-free.

  ed25519   an asymmetric key. Point AIRLOCK_SIGN_KEY at the private key and
            keep it somewhere the agent cannot read (an HSM, a signing service,
            a different uid). This is what a regulated buyer actually wants,
            because the verifier only ever needs the public half.

Off by default: it is a real guarantee only when the key is genuinely separated,
and pretending otherwise would be the kind of security theatre this project is
supposed to be the opposite of.
"""
from __future__ import annotations
import hashlib
import hmac
import os
from pathlib import Path

from . import config

ALG_NONE, ALG_HMAC, ALG_ED25519 = "none", "hmac-sha256", "ed25519"


def key_path() -> Path:
    return Path(os.environ.get("AIRLOCK_SIGN_KEY", config.home() / "audit.key"))


def mode() -> str:
    """What signing is configured right now."""
    m = os.environ.get("AIRLOCK_SIGN", "").lower()
    if m in ("0", "false", "off", "none", ""):
        return ALG_NONE if m else (ALG_HMAC if key_path().exists() else ALG_NONE)
    if m in ("1", "true", "on", "hmac", ALG_HMAC):
        return ALG_HMAC
    if m in ("ed25519", ALG_ED25519):
        return ALG_ED25519
    return ALG_NONE


def ensure_key() -> Path:
    p = key_path()
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        old = os.umask(0o177)
        try:
            p.write_bytes(os.urandom(32))
        finally:
            os.umask(old)
        os.chmod(p, 0o600)
    return p


def _hmac_key() -> bytes:
    """The key for *writing* a signature — created on first use if absent."""
    return ensure_key().read_bytes()


def _hmac_key_ro() -> bytes | None:
    """The key for *verifying* — read only, never created.

    Verification is a read-only operation. Routing it through ensure_key() (as
    it once did) meant `airlock verify` would materialise a fresh random key at
    AIRLOCK_SIGN_KEY when the real one was missing — writing a file into the cwd
    for a relative path, then reporting every signature as broken against a key
    that had nothing to do with the log. Read, or report unavailable.
    """
    try:
        return key_path().read_bytes()
    except OSError:
        return None


def can_verify(alg: str) -> bool:
    """Is the material needed to verify this algorithm actually available?

    Lets a caller tell "the signature is wrong" (tampering) apart from "I could
    not check the signature" (missing key) — two very different verdicts.
    """
    if alg == ALG_HMAC:
        return _hmac_key_ro() is not None
    if alg == ALG_ED25519:
        return public_key() is not None
    return True


def _ed25519_private():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    raw = key_path().read_bytes()
    if raw.lstrip().startswith(b"-----BEGIN"):
        return serialization.load_pem_private_key(raw, password=None)
    return Ed25519PrivateKey.from_private_bytes(raw[:32])


def sign(digest: str) -> str:
    """Return a signature over a record digest, or "" when signing is off."""
    m = mode()
    try:
        if m == ALG_HMAC:
            return hmac.new(_hmac_key(), digest.encode(), hashlib.sha256).hexdigest()[:32]
        if m == ALG_ED25519:
            return _ed25519_private().sign(digest.encode()).hex()
    except Exception:
        return ""
    return ""


def verify_one(digest: str, signature: str, alg: str) -> bool:
    try:
        if alg == ALG_HMAC:
            key = _hmac_key_ro()
            if key is None:
                return False
            want = hmac.new(key, digest.encode(), hashlib.sha256).hexdigest()[:32]
            return hmac.compare_digest(want, signature)
        if alg == ALG_ED25519:
            pub = public_key()
            if pub is None:
                return False
            pub.verify(bytes.fromhex(signature), digest.encode())
            return True
    except Exception:
        return False
    return False


def public_key():
    """The public half, for a verifier that must not hold the private key."""
    try:
        pubpath = os.environ.get("AIRLOCK_VERIFY_KEY")
        if pubpath:
            from cryptography.hazmat.primitives import serialization
            return serialization.load_pem_public_key(Path(pubpath).read_bytes())
        return _ed25519_private().public_key()
    except Exception:
        return None


def generate_ed25519(dest: Path) -> tuple[Path, Path]:
    """Write a private/public keypair. The private half belongs off this box."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    k = Ed25519PrivateKey.generate()
    priv = dest
    pub = dest.with_suffix(dest.suffix + ".pub")
    old = os.umask(0o177)
    try:
        priv.write_bytes(k.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    finally:
        os.umask(old)
    os.chmod(priv, 0o600)
    pub.write_bytes(k.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub
