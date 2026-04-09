import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import tempfile
from pathlib import Path
from micropki import crypto_utils


def test_generate_rsa_key():

    key = crypto_utils.generate_rsa_key(4096)
    assert key is not None
    assert key.key_size == 4096

    key = crypto_utils.generate_rsa_key(2048)
    assert key is not None
    assert key.key_size == 2048

    with pytest.raises(ValueError, match="RSA key size must be 2048 or 4096 bits"):
        crypto_utils.generate_rsa_key(1024)

    with pytest.raises(ValueError, match="RSA key size must be 2048 or 4096 bits"):
        crypto_utils.generate_rsa_key(3072)

    with pytest.raises(ValueError, match="RSA key size must be 2048 or 4096 bits"):
        crypto_utils.generate_rsa_key(512)


def test_generate_ecc_key():

    key = crypto_utils.generate_ecc_key(384)
    assert key is not None
    assert key.curve.name == "secp384r1"

    key = crypto_utils.generate_ecc_key(256)
    assert key is not None
    assert key.curve.name == "secp256r1"

    with pytest.raises(ValueError, match="ECC key size must be 256 or 384 bits"):
        crypto_utils.generate_ecc_key(521)

    with pytest.raises(ValueError, match="ECC key size must be 256 or 384 bits"):
        crypto_utils.generate_ecc_key(192)

    with pytest.raises(ValueError, match="ECC key size must be 256 or 384 bits"):
        crypto_utils.generate_ecc_key(224)


def test_passphrase_loading():

    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"testpassphrase\n")
        f.flush()
        passphrase = crypto_utils.load_passphrase(Path(f.name))
        assert passphrase == b"testpassphrase"

    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"testpassphrase\r\n")
        f.flush()
        passphrase = crypto_utils.load_passphrase(Path(f.name))
        assert passphrase == b"testpassphrase"

    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"anotherpass")
        f.flush()
        passphrase = crypto_utils.load_passphrase(Path(f.name))
        assert passphrase == b"anotherpass"

    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"multiline\npass\n")
        f.flush()
        passphrase = crypto_utils.load_passphrase(Path(f.name))
        assert passphrase == b"multiline\npass"


def test_generate_serial_number():

    serial = crypto_utils.generate_serial_number()
    assert serial > 0

    assert serial.bit_length() >= 20

    assert serial.bit_length() < 160


    serials = [crypto_utils.generate_serial_number() for _ in range(10)]
    assert len(set(serials)) == 10


def test_key_encryption():

    key = crypto_utils.generate_rsa_key(2048)
    passphrase = b"testpass"

    encrypted = crypto_utils.encrypt_private_key(key, passphrase)
    assert encrypted is not None
    assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in encrypted

    ecc_key = crypto_utils.generate_ecc_key(256)
    encrypted_ecc = crypto_utils.encrypt_private_key(ecc_key, passphrase)
    assert encrypted_ecc is not None
    assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in encrypted_ecc


def test_load_encrypted_private_key():

    # Create a key and encrypt it
    key = crypto_utils.generate_rsa_key(2048)
    passphrase = b"secret123"
    encrypted = crypto_utils.encrypt_private_key(key, passphrase)


    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(encrypted)
        temp_path = Path(f.name)

    try:

        loaded_key = crypto_utils.load_encrypted_private_key(temp_path, passphrase)
        assert loaded_key is not None
        assert loaded_key.key_size == 2048


        with pytest.raises(Exception):
            crypto_utils.load_encrypted_private_key(temp_path, b"wrongpass")
    finally:
        temp_path.unlink()


def test_verify_key_pair():

    rsa_private = crypto_utils.generate_rsa_key(2048)
    rsa_public = rsa_private.public_key()
    assert crypto_utils.verify_key_pair(rsa_private, rsa_public) is True


    wrong_private = crypto_utils.generate_rsa_key(2048)
    wrong_public = wrong_private.public_key()
    assert crypto_utils.verify_key_pair(rsa_private, wrong_public) is False


    ecc_private = crypto_utils.generate_ecc_key(256)
    ecc_public = ecc_private.public_key()
    assert crypto_utils.verify_key_pair(ecc_private, ecc_public) is True