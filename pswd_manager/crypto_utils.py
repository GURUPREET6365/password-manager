import base64 # This is needed for key encoding
from cryptography.fernet import Fernet # This is for encryption/decryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # This is for key derivation. Derivation is the process of making a key from password
from cryptography.hazmat.primitives import hashes # This is for hashing algorithm
from cryptography.hazmat.backends import default_backend # This is for backend

# --- Helper to make a key from user's master password ---
def derive_user_key(master_password: str, salt: bytes) -> bytes:
    """
    Derives a unique encryption key for each user
    using their master password + salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


# --- Encrypt password using a user's key ---
def encrypt_password(plain_password: str, user_key: str) -> str:
    """
    Encrypts a plain password using user's key.
    user_key should come from session["user_key"] after login.
    """
    cipher = Fernet(user_key.encode())
    encrypted = cipher.encrypt(plain_password.encode())
    return encrypted.decode()  # store as text in DB


# --- Decrypt password using a user's key ---
def decrypt_password(encrypted_password: str, user_key: str) -> str:
    """
    Decrypts an encrypted password using user's key.
    user_key should come from session["user_key"] after login.
    """
    cipher = Fernet(user_key.encode())
    decrypted = cipher.decrypt(encrypted_password.encode())
    return decrypted.decode()
