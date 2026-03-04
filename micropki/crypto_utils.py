"""Cryptographic utilities for key generation and handling."""

import os
import secrets
from pathlib import Path
from typing import Union, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def generate_rsa_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """
    Generate an RSA private key.

    Args:
        key_size: Key size in bits (must be 4096 for this implementation)

    Returns:
        RSA private key
    """
    if key_size != 4096:
        raise ValueError("RSA key size must be 4096 bits")

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_ecc_key(key_size: int = 384) -> ec.EllipticCurvePrivateKey:
    """
    Generate an ECC private key on P-384 curve.

    Args:
        key_size: Key size (must be 384 for P-384 curve)

    Returns:
        ECC private key
    """
    if key_size != 384:
        raise ValueError("ECC key size must be 384 bits (P-384 curve)")

    return ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )


def encrypt_private_key(
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        passphrase: bytes
) -> bytes:
    """
    Encrypt a private key with a passphrase.

    Args:
        private_key: The private key to encrypt
        passphrase: The passphrase as bytes

    Returns:
        PEM-encoded encrypted private key
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )


def save_private_key(key_data: bytes, key_path: Path) -> None:
    """
    Save encrypted private key with secure permissions.

    Args:
        key_data: PEM-encoded encrypted private key
        key_path: Path where to save the key
    """
    # Ensure parent directory exists
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Write key with secure permissions
    with open(key_path, 'wb') as f:
        f.write(key_data)

    # Set file permissions to 0o600 (owner read/write only)
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        # Windows may not support chmod, ignore
        pass


def load_passphrase(passphrase_file: Path) -> bytes:
    """
    Load passphrase from file and strip trailing whitespace.

    Args:
        passphrase_file: Path to passphrase file

    Returns:
        Passphrase as bytes
    """
    if not passphrase_file.exists():
        raise FileNotFoundError(f"Passphrase file not found: {passphrase_file}")

    with open(passphrase_file, 'rb') as f:
        # Strip all trailing whitespace
        passphrase = f.read().rstrip()

    return passphrase


def generate_serial_number() -> int:
    """
    Generate a cryptographically secure random serial number.

    Returns:
        Positive integer with at least 20 bits of randomness and not more than 159 bits
    """
    # Generate 19 bytes of randomness (152 bits) to ensure it's <= 159 bits
    # This guarantees the most significant bit is 0
    random_bytes = secrets.token_bytes(19)
    # Convert to integer
    serial = int.from_bytes(random_bytes, byteorder='big')
    # Ensure it's positive and not too large
    return serial


def verify_key_pair(
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
) -> bool:
    """
    Verify that a private key corresponds to a public key.

    Args:
        private_key: The private key
        public_key: The public key to verify against

    Returns:
        True if the keys match, False otherwise
    """
    try:
        if isinstance(private_key, rsa.RSAPrivateKey):
            # Test RSA key pair
            message = b"Test message for key verification"
            signature = private_key.sign(
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        else:  # ECC
            message = b"Test message for key verification"
            signature = private_key.sign(message, ec.ECDSA(hashes.SHA384()))
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA384()))

        return True
    except Exception:
        return False


def load_encrypted_private_key(key_path: Path, passphrase: bytes) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
    """
    Load and decrypt an encrypted private key from a PEM file.

    Args:
        key_path: Path to the encrypted private key file
        passphrase: Passphrase to decrypt the key

    Returns:
        Decrypted private key
    """
    with open(key_path, 'rb') as f:
        key_data = f.read()

    private_key = serialization.load_pem_private_key(
        key_data,
        password=passphrase,
        backend=default_backend()
    )

    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise TypeError("Loaded key is not a private key")

    return private_key