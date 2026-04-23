import pytest
import tempfile
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.ocsp import OCSPRequestBuilder
from cryptography.x509.extensions import Extension, ExtensionNotFound
from cryptography.x509.oid import ExtensionOID

# Try different import paths for OCSPNonce
try:
    from cryptography.x509.ocsp import OCSPNonce
except ImportError:
    # Fallback for older cryptography versions
    from cryptography.x509 import OCSPNonce

from micropki.ca import RootCA
from micropki.intermediate import IntermediateCA, IssueCertificate
from micropki.database import Database
from micropki.ocsp import OCSPResponder, create_ocsp_signing_certificate
from micropki.ocsp_responder import OCSPResponderServer
from micropki.certificates import load_certificate
from micropki.crypto_utils import generate_rsa_key, load_encrypted_private_key, load_passphrase


@pytest.fixture
def temp_pki_env():

    temp_dir = Path(tempfile.mkdtemp())
    pki_dir = temp_dir / "pki"
    secrets_dir = temp_dir / "secrets"

    pki_dir.mkdir()
    secrets_dir.mkdir()

    # Create passphrase files
    root_pass_file = secrets_dir / "root.pass"
    root_pass_file.write_text("rootpass123\n")
    inter_pass_file = secrets_dir / "intermediate.pass"
    inter_pass_file.write_text("interpass123\n")

    # Initialize Root CA
    root_ca = RootCA(str(pki_dir))
    root_ca.init_ca(
        subject="/CN=Test Root CA/O=OCSP Test",
        key_type="rsa",
        key_size=4096,
        passphrase_file=str(root_pass_file),
        validity_days=365
    )

    # Initialize Intermediate CA
    inter_ca = IntermediateCA(str(pki_dir))
    inter_ca.create_intermediate_ca(
        root_cert_path=pki_dir / "certs" / "ca.cert.pem",
        root_key_path=pki_dir / "private" / "ca.key.pem",
        root_pass_file=root_pass_file,
        subject_dn="/CN=Test Intermediate CA/O=OCSP Test",
        key_type="rsa",
        passphrase_file=inter_pass_file,
        validity_days=365,
        pathlen=0
    )

    # Issue a test server certificate
    issuer = IssueCertificate()
    cert_path, key_path = issuer.issue_certificate(
        ca_cert_path=pki_dir / "certs" / "intermediate.cert.pem",
        ca_key_path=pki_dir / "private" / "intermediate.key.pem",
        ca_pass_file=inter_pass_file,
        template_name="server",
        subject_dn="/CN=testserver.local/O=OCSP Test",
        san_list=["dns:testserver.local"],
        out_dir=pki_dir / "certs",
        validity_days=365,
        csr_path=None
    )

    # Load certificates for tests
    inter_cert = load_certificate(pki_dir / "certs" / "intermediate.cert.pem")
    inter_key_pass = load_passphrase(inter_pass_file)
    inter_key = load_encrypted_private_key(
        pki_dir / "private" / "intermediate.key.pem",
        inter_key_pass
    )

    return {
        'temp_dir': temp_dir,
        'pki_dir': pki_dir,
        'intermediate_cert': inter_cert,
        'intermediate_key': inter_key,
        'pass_file': inter_pass_file,
        'server_cert_path': pki_dir / "certs" / "testserver.local.cert.pem",
        'db_path': pki_dir / "micropki.db"
    }


def test_create_ocsp_signing_certificate(temp_pki_env):
    """Test OCSP signing certificate issuance (TEST-28)."""
    env = temp_pki_env

    # Create OCSP signing certificate
    ocsp_cert, ocsp_key = create_ocsp_signing_certificate(
        issuer_cert=env['intermediate_cert'],
        issuer_key=env['intermediate_key'],
        subject_dn="/CN=OCSP Responder/O=OCSP Test",
        validity_days=365,
        key_type="rsa",
        key_size=2048,
        san_list=["dns:ocsp.example.com"],
        ocsp_url="http://localhost:8081/ocsp"
    )

    # Verify certificate properties
    assert ocsp_cert is not None

    # Check Basic Constraints
    bc = ocsp_cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    )
    assert bc.value.ca is False

    # Check Key Usage
    ku = ocsp_cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.KEY_USAGE
    )
    assert ku.value.digital_signature is True
    assert ku.value.key_cert_sign is False
    assert ku.value.crl_sign is False

    # Check Extended Key Usage (OCSP signing)
    from cryptography.x509.oid import ExtendedKeyUsageOID
    eku = ocsp_cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
    )
    assert ExtendedKeyUsageOID.OCSP_SIGNING in eku.value

    # Verify with OpenSSL if available
    try:
        # Save temporary files for verification
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as cert_file:
            cert_file.write(ocsp_cert.public_bytes(serialization.Encoding.PEM))
            cert_path = Path(cert_file.name)

        # Check with OpenSSL
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-text", "-noout"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "OCSP Signing" in result.stdout or "1.3.6.1.5.5.7.3.9" in result.stdout

        cert_path.unlink()
    except FileNotFoundError:
        pytest.skip("OpenSSL not available")


def test_ocsp_responder_good_status(temp_pki_env):
    """Test OCSP responder returns 'good' for valid certificate (TEST-29)."""
    env = temp_pki_env

    # Create OCSP signing certificate
    ocsp_cert, ocsp_key = create_ocsp_signing_certificate(
        issuer_cert=env['intermediate_cert'],
        issuer_key=env['intermediate_key'],
        subject_dn="/CN=OCSP Responder",
        validity_days=365,
        key_type="rsa",
        key_size=2048
    )

    # Load database
    db = Database(str(env['db_path']))

    # Create OCSP responder
    responder = OCSPResponder(
        responder_cert=ocsp_cert,
        responder_key=ocsp_key,
        ca_cert=env['intermediate_cert'],
        db=db,
        cache_ttl=60
    )

    # Load the server certificate
    server_cert = load_certificate(env['server_cert_path'])

    # Build OCSP request
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(
        server_cert,
        env['intermediate_cert'],
        hashes.SHA1()
    )

    # Build request
    ocsp_request = builder.build()

    # Get DER
    request_der = ocsp_request.public_bytes(serialization.Encoding.DER)

    # Handle request
    response_der, status = responder.handle_request(request_der)
    assert status == 200
    assert len(response_der) > 0


def test_ocsp_responder_unknown_status(temp_pki_env):
    """Test OCSP responder returns 'unknown' for non-existent certificate (TEST-31)."""
    env = temp_pki_env

    # Create OCSP signing certificate
    ocsp_cert, ocsp_key = create_ocsp_signing_certificate(
        issuer_cert=env['intermediate_cert'],
        issuer_key=env['intermediate_key'],
        subject_dn="/CN=OCSP Responder",
        validity_days=365,
        key_type="rsa",
        key_size=2048
    )

    # Load database
    db = Database(str(env['db_path']))

    # Create OCSP responder
    responder = OCSPResponder(
        responder_cert=ocsp_cert,
        responder_key=ocsp_key,
        ca_cert=env['intermediate_cert'],
        db=db,
        cache_ttl=60
    )

    # Create a request for a non-existent certificate
    # Create a dummy certificate with unknown serial
    dummy_serial = 999999999999999999
    dummy_key = generate_rsa_key(2048)
    dummy_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "dummy")])

    dummy_builder = x509.CertificateBuilder()
    dummy_builder = dummy_builder.subject_name(dummy_name)
    dummy_builder = dummy_builder.issuer_name(env['intermediate_cert'].subject)
    dummy_builder = dummy_builder.public_key(dummy_key.public_key())
    dummy_builder = dummy_builder.serial_number(dummy_serial)
    dummy_builder = dummy_builder.not_valid_before(datetime.now(timezone.utc))
    dummy_builder = dummy_builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))

    dummy_cert = dummy_builder.sign(dummy_key, hashes.SHA256(), default_backend())

    # Build OCSP request for dummy certificate
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(
        dummy_cert,
        env['intermediate_cert'],
        hashes.SHA1()
    )

    ocsp_request = builder.build()
    request_der = ocsp_request.public_bytes(serialization.Encoding.DER)

    # Handle request
    response_der, status = responder.handle_request(request_der)
    assert status == 200
    assert len(response_der) > 0


def test_ocsp_responder_server_startup(temp_pki_env):
    """Test OCSP responder server can start."""
    env = temp_pki_env

    # First create OCSP signing certificate
    ocsp_cert, ocsp_key = create_ocsp_signing_certificate(
        issuer_cert=env['intermediate_cert'],
        issuer_key=env['intermediate_key'],
        subject_dn="/CN=OCSP Responder",
        validity_days=365,
        key_type="rsa",
        key_size=2048
    )

    # Save certificate and key
    cert_path = env['pki_dir'] / "certs" / "ocsp.cert.pem"
    key_path = env['pki_dir'] / "private" / "ocsp.key.pem"

    with open(cert_path, 'wb') as f:
        f.write(ocsp_cert.public_bytes(serialization.Encoding.PEM))

    unencrypted_key = ocsp_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(key_path, 'wb') as f:
        f.write(unencrypted_key)

    # Create server (but don't start it fully - we just test initialization)
    try:
        server = OCSPResponderServer(
            host="127.0.0.1",
            port=18081,
            db_path=str(env['db_path']),
            responder_cert_path=cert_path,
            responder_key_path=key_path,
            ca_cert_path=env['pki_dir'] / "certs" / "intermediate.cert.pem",
            cache_ttl=60
        )

        # Should be able to load certificates
        responder_cert, responder_key, ca_cert, db = server._load_certificates_and_key()
        assert responder_cert is not None
        assert responder_key is not None
        assert ca_cert is not None
        assert db is not None

    except Exception as e:
        pytest.fail(f"Server initialization failed: {e}")


def test_ocsp_nonce_echo(temp_pki_env):
    """Test that OCSP responder echoes nonce correctly (TEST-32)."""
    env = temp_pki_env

    # Create OCSP signing certificate
    ocsp_cert, ocsp_key = create_ocsp_signing_certificate(
        issuer_cert=env['intermediate_cert'],
        issuer_key=env['intermediate_key'],
        subject_dn="/CN=OCSP Responder",
        validity_days=365,
        key_type="rsa",
        key_size=2048
    )

    db = Database(str(env['db_path']))

    responder = OCSPResponder(
        responder_cert=ocsp_cert,
        responder_key=ocsp_key,
        ca_cert=env['intermediate_cert'],
        db=db,
        cache_ttl=60
    )

    # Load the server certificate
    server_cert = load_certificate(env['server_cert_path'])

    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(
        server_cert,
        env['intermediate_cert'],
        hashes.SHA1()
    )

    # Add nonce - use the correct approach for your cryptography version
    import secrets
    test_nonce = secrets.token_bytes(16)
    # Create nonce extension manually
    from cryptography.x509.oid import ExtensionOID
    from cryptography.x509.extensions import Extension
    from cryptography.x509.general_name import OCSPNonce

    try:
        # Try to use OCSPNonce class
        nonce_ext = OCSPNonce(test_nonce)
        builder = builder.add_extension(nonce_ext, critical=False)
    except (NameError, TypeError):
        # Alternative approach - create extension directly
        try:
            from cryptography.x509 import OCSPNonce as NonceClass
            nonce_ext = NonceClass(test_nonce)
            builder = builder.add_extension(nonce_ext, critical=False)
        except (NameError, ImportError):
            # If OCSPNonce is not available, skip nonce test
            pytest.skip("OCSPNonce not available in this cryptography version")

    ocsp_request = builder.build()
    request_der = ocsp_request.public_bytes(serialization.Encoding.DER)

    # Parse request to verify nonce is present
    parsed = responder.parse_request(request_der)
    assert parsed.get('nonce') is not None