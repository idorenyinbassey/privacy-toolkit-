"""
Config persistence: proxy lists, bridge lines, redsocks target, and
VPN config paths, saved so you're not retyping the same proxy chain
or bridge set every session. Encrypted at rest (same PBKDF2 + Fernet
approach as crypto_log.py) since a proxy list can contain
authentication credentials.
"""
import base64
import json
import os
from pathlib import Path

PROFILE_DIR = Path.home() / ".privacyguard_profiles"


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def save_profile(name: str, data: dict, passphrase: str) -> Path:
    """data: e.g. {'proxies': [...], 'chain_mode': 'dynamic',
    'include_tor': False, 'bridges': [...], 'redsocks_host': ...,
    'redsocks_port': ..., 'vpn_config': ...}"""
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise RuntimeError("cryptography not installed. pip install cryptography --break-system-packages")

    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(16)
    key = _derive_key(passphrase, salt)
    token = Fernet(key).encrypt(json.dumps(data).encode())
    path = PROFILE_DIR / f"{name}.profile.enc"
    path.write_bytes(salt + token)
    print(f"[+] Profile '{name}' saved to {path}.")
    return path


def load_profile(name: str, passphrase: str) -> dict:
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError:
        raise RuntimeError("cryptography not installed.")

    path = PROFILE_DIR / f"{name}.profile.enc"
    if not path.exists():
        raise FileNotFoundError(f"No profile named '{name}' at {path}")
    raw = path.read_bytes()
    salt, token = raw[:16], raw[16:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    plaintext = Fernet(key).decrypt(token)
    return json.loads(plaintext.decode())


def list_profiles() -> list:
    if not PROFILE_DIR.exists():
        return []
    return sorted(p.stem.replace(".profile", "") for p in PROFILE_DIR.glob("*.profile.enc"))


def delete_profile(name: str) -> bool:
    path = PROFILE_DIR / f"{name}.profile.enc"
    if path.exists():
        path.unlink()
        return True
    return False
