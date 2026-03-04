"""Tests for cryptographic utilities."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import tempfile
from pathlib import Path
from micropki import crypto_utils


def test_generate_rsa_key():
    """Test RSA key generation."""
    key = crypto_utils.generate_rsa_key(4096)
    assert key is not None
    assert key.key_size == 4096

    with pytest.raises(ValueError):
        crypto_utils.generate_rsa_key(2048)


def test_generate_ecc_key():
    """Test ECC key generation."""
    key = crypto_utils.generate_ecc_key(384)
    assert key is not None
    assert key.curve.name == "secp384r1"

    with pytest.raises(ValueError):
        crypto_utils.generate_ecc_key(256)


def test_passphrase_loading():
    """Test passphrase loading from file."""
    # Test with newline
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"testpassphrase\n")
        f.flush()
        passphrase = crypto_utils.load_passphrase(Path(f.name))
        assert passphrase == b"testpassphrase"

    # Test with carriage return and newline
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"testpassphrase\r\n")
        f.flush()
        passphrase = crypto_utils.load_passphrase(Path(f.name))
        assert passphrase == b"testpassphrase"

    # Test without newline (create a new file)
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"anotherpass")
        f.flush()
        passphrase = crypto_utils.load_passphrase(Path(f.name))
        assert passphrase == b"anotherpass"


def test_generate_serial_number():
    """Test serial number generation."""
    serial = crypto_utils.generate_serial_number()
    assert serial > 0
    # Check that it's at least 20 bits
    assert serial.bit_length() >= 20
    # Check that it's not more than 159 bits
    assert serial.bit_length() < 160


def test_key_encryption():
    """Test private key encryption."""
    key = crypto_utils.generate_rsa_key(4096)
    passphrase = b"testpass"

    encrypted = crypto_utils.encrypt_private_key(key, passphrase)
    assert encrypted is not None
    assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in encrypted