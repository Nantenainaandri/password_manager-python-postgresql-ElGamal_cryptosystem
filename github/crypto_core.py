import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_fernet_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # adjust for your hardware
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))
    return key  # must be 32 bytes, url-safe base64 for Fernet

def encrypt_secret(fernet_key: bytes, plaintext: str) -> bytes:
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode("utf-8"))

def decrypt_secret(fernet_key: bytes, token: bytes) -> str:
    f = Fernet(fernet_key)
    return f.decrypt(token).decode("utf-8")