"""Tests for CA functionality."""

import pytest
import tempfile
import shutil
from pathlib import Path
from micropki.ca import RootCA
from micropki.certificates import verify_certificate
from micropki.crypto_utils import load_passphrase, load_encrypted_private_key, verify_key_pair


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    path = Path(tempfile.mkdtemp())
    yield path
    shutil.rmtree(path)


@pytest.fixture
def passphrase_file(temp_dir):
    """Create a passphrase file."""
    pass_file = temp_dir / "pass.txt"
    pass_file.write_text("testpassphrase\n")
    return pass_file


def test_ca_initialization_rsa(temp_dir, passphrase_file):
    """Test RSA CA initialization."""
    ca = RootCA(str(temp_dir / "pki"))
    ca.init_ca(
        subject="/CN=Test Root CA/O=Testing",
        key_type="rsa",
        key_size=4096,
        passphrase_file=str(passphrase_file),
        validity_days=365
    )

    # Check files were created
    assert (temp_dir / "pki/private/ca.key.pem").exists()
    assert (temp_dir / "pki/certs/ca.cert.pem").exists()
    assert (temp_dir / "pki/policy.txt").exists()

    # Verify certificate
    cert_path = temp_dir / "pki/certs/ca.cert.pem"
    assert verify_certificate(cert_path) is True


def test_ca_initialization_ecc(temp_dir, passphrase_file):
    """Test ECC CA initialization."""
    ca = RootCA(str(temp_dir / "pki"))
    ca.init_ca(
        subject="CN=Test ECC Root CA,O=Testing",
        key_type="ecc",
        key_size=384,
        passphrase_file=str(passphrase_file),
        validity_days=365
    )

    # Check files were created
    assert (temp_dir / "pki/private/ca.key.pem").exists()
    assert (temp_dir / "pki/certs/ca.cert.pem").exists()
    assert (temp_dir / "pki/policy.txt").exists()

    # Verify certificate
    cert_path = temp_dir / "pki/certs/ca.cert.pem"
    assert verify_certificate(cert_path) is True


def test_key_and_certificate_match(temp_dir, passphrase_file):
    """Test that private key matches certificate."""
    ca = RootCA(str(temp_dir / "pki"))
    ca.init_ca(
        subject="/CN=Test Root CA",
        key_type="rsa",
        key_size=4096,
        passphrase_file=str(passphrase_file),
        validity_days=365
    )

    # FIXED: Load and decrypt key, then verify against cert
    cert_path = temp_dir / "pki/certs/ca.cert.pem"
    key_path = temp_dir / "pki/private/ca.key.pem"
    passphrase = load_passphrase(passphrase_file)

    # Load certificate
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Load and decrypt private key
    private_key = load_encrypted_private_key(key_path, passphrase)

    # Verify key pair
    assert verify_key_pair(private_key, certificate.public_key()) is True


# FIXED: New test for TEST-3
def test_encrypted_key_loading(temp_dir, passphrase_file):
    """Test that encrypted private key can be loaded and decrypted."""
    ca = RootCA(str(temp_dir / "pki"))
    ca.init_ca(
        subject="/CN=Test Root CA",
        key_type="rsa",
        key_size=4096,
        passphrase_file=str(passphrase_file),
        validity_days=365
    )

    key_path = temp_dir / "pki/private/ca.key.pem"
    passphrase = load_passphrase(passphrase_file)

    # This should not raise an exception
    private_key = load_encrypted_private_key(key_path, passphrase)
    assert private_key is not None
    assert private_key.key_size == 4096