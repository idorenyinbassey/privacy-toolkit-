"""
Keep a private, encrypted record of what PrivacyGuard did this session
(useful for your own engagement notes/report) even though the *system*
traces (bash history, logs) get wiped by the cleanup module. The log
is encrypted at rest with a passphrase you choose — only you can read
it back.
"""
import base64
import json
import os
import time
from pathlib import Path

LOG_DIR = Path.home() / ".privacyguard_logs"


class EncryptedLogger:
    def __init__(self):
        self.buffer = []

    def log(self, message: str) -> None:
        entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "msg": message}
        self.buffer.append(entry)

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
        return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

    def save(self, passphrase: str, label: str = None) -> Path:
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise RuntimeError(
                "cryptography not installed. pip install cryptography --break-system-packages "
                "(Termux may need: pkg install rust clang && pip install cryptography)"
            )
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(16)
        key = self._derive_key(passphrase, salt)
        token = Fernet(key).encrypt(json.dumps(self.buffer).encode())

        fname = f"session-{label or time.strftime('%Y%m%d-%H%M%S')}.enc"
        path = LOG_DIR / fname
        # store salt + ciphertext together, salt first 16 bytes
        path.write_bytes(salt + token)
        print(f"[+] Encrypted log saved to {path} ({len(self.buffer)} entries).")
        print("    Keep the passphrase safe — it cannot be recovered if lost.")
        return path

    @staticmethod
    def decrypt(path, passphrase: str) -> list:
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        except ImportError:
            raise RuntimeError("cryptography not installed.")
        data = Path(path).read_bytes()
        salt, token = data[:16], data[16:]
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        plaintext = Fernet(key).decrypt(token)
        return json.loads(plaintext.decode())


def list_saved_logs() -> list:
    if not LOG_DIR.exists():
        return []
    return sorted(LOG_DIR.glob("session-*.enc"))
