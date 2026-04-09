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

    if key_size not in [2048, 4096]:
        raise ValueError("RSA key size must be 2048 or 4096 bits")

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_ecc_key(key_size: int = 384) -> ec.EllipticCurvePrivateKey:

    if key_size == 384:
        curve = ec.SECP384R1()
    elif key_size == 256:
        curve = ec.SECP256R1()
    else:
        raise ValueError("ECC key size must be 256 or 384 bits")

    return ec.generate_private_key(
        curve=curve,
        backend=default_backend()
    )


def encrypt_private_key(
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        passphrase: bytes
) -> bytes:

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )


def save_private_key(key_data: bytes, key_path: Path) -> None:

    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    with open(key_path, 'wb') as f:
        f.write(key_data)

    try:
        os.chmod(key_path, 0o600)
    except Exception:

        pass


def load_passphrase(passphrase_file: Path) -> bytes:

    if not passphrase_file.exists():
        raise FileNotFoundError(f"Passphrase file not found: {passphrase_file}")

    with open(passphrase_file, 'rb') as f:

        passphrase = f.read().rstrip()

    return passphrase


def generate_serial_number() -> int:

    random_bytes = secrets.token_bytes(19)

    serial = int.from_bytes(random_bytes, byteorder='big')

    return serial


def verify_key_pair(
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
) -> bool:

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