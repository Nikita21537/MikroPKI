import pytest
import tempfile
import shutil
from pathlib import Path
from micropki.ca import RootCA
from micropki.certificates import verify_certificate
from micropki.crypto_utils import load_passphrase, load_encrypted_private_key, verify_key_pair


@pytest.fixture
def temp_dir():

    path = Path(tempfile.mkdtemp())
    yield path
    shutil.rmtree(path)


@pytest.fixture
def passphrase_file(temp_dir):

    pass_file = temp_dir / "pass.txt"
    pass_file.write_text("testpassphrase\n")
    return pass_file


def test_ca_initialization_rsa(temp_dir, passphrase_file):

    ca = RootCA(str(temp_dir / "pki"))
    ca.init_ca(
        subject="/CN=Test Root CA/O=Testing",
        key_type="rsa",
        key_size=4096,
        passphrase_file=str(passphrase_file),
        validity_days=365
    )


    assert (temp_dir / "pki/private/ca.key.pem").exists()
    assert (temp_dir / "pki/certs/ca.cert.pem").exists()
    assert (temp_dir / "pki/policy.txt").exists()


    cert_path = temp_dir / "pki/certs/ca.cert.pem"
    assert verify_certificate(cert_path) is True


def test_ca_initialization_ecc(temp_dir, passphrase_file):

    ca = RootCA(str(temp_dir / "pki"))
    ca.init_ca(
        subject="CN=Test ECC Root CA,O=Testing",
        key_type="ecc",
        key_size=384,
        passphrase_file=str(passphrase_file),
        validity_days=365
    )


    assert (temp_dir / "pki/private/ca.key.pem").exists()
    assert (temp_dir / "pki/certs/ca.cert.pem").exists()
    assert (temp_dir / "pki/policy.txt").exists()


    cert_path = temp_dir / "pki/certs/ca.cert.pem"
    assert verify_certificate(cert_path) is True


def test_key_and_certificate_match(temp_dir, passphrase_file):

    ca = RootCA(str(temp_dir / "pki"))
    ca.init_ca(
        subject="/CN=Test Root CA",
        key_type="rsa",
        key_size=4096,
        passphrase_file=str(passphrase_file),
        validity_days=365
    )


    cert_path = temp_dir / "pki/certs/ca.cert.pem"
    key_path = temp_dir / "pki/private/ca.key.pem"
    passphrase = load_passphrase(passphrase_file)


    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    certificate = x509.load_pem_x509_certificate(cert_data, default_backend())


    private_key = load_encrypted_private_key(key_path, passphrase)


    assert verify_key_pair(private_key, certificate.public_key()) is True


def test_encrypted_key_loading(temp_dir, passphrase_file):

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


def test_ca_initialization_invalid_key_size(temp_dir, passphrase_file):

    ca = RootCA(str(temp_dir / "pki"))


    with pytest.raises(ValueError, match="RSA key size for Root CA must be 4096 bits"):
        ca.init_ca(
            subject="/CN=Test",
            key_type="rsa",
            key_size=2048,
            passphrase_file=str(passphrase_file),
            validity_days=365
        )


    with pytest.raises(ValueError, match="RSA key size for Root CA must be 4096 bits"):
        ca.init_ca(
            subject="/CN=Test",
            key_type="rsa",
            key_size=1024,
            passphrase_file=str(passphrase_file),
            validity_days=365
        )


    with pytest.raises(ValueError, match="ECC key size for Root CA must be 384 bits"):
        ca.init_ca(
            subject="/CN=Test",
            key_type="ecc",
            key_size=256,
            passphrase_file=str(passphrase_file),
            validity_days=365
        )


    with pytest.raises(ValueError, match="ECC key size for Root CA must be 384 bits"):
        ca.init_ca(
            subject="/CN=Test",
            key_type="ecc",
            key_size=521,
            passphrase_file=str(passphrase_file),
            validity_days=365
        )
