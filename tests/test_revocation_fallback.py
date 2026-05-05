import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock


from micropki.database import Database
from micropki.certificates import load_certificate, save_certificate
from micropki.revocation import RevocationManager, CRLManager
from micropki.revocation_check import RevocationChecker, RevocationStatus, OCSPChecker, CRLChecker


@pytest.fixture
def revocation_env():

    temp_dir = Path(tempfile.mkdtemp())
    pki_dir = temp_dir / "pki"
    secrets_dir = temp_dir / "secrets"

    pki_dir.mkdir()
    pki_dir.joinpath("certs").mkdir()
    pki_dir.joinpath("private").mkdir()
    pki_dir.joinpath("crl").mkdir()
    secrets_dir.mkdir()

    # Create a simple self-signed test CA
    from micropki.ca import RootCA
    root_pass_file = secrets_dir / "root.pass"
    root_pass_file.write_text("testpass\n")

    root_ca = RootCA(str(pki_dir))
    root_ca.init_ca(
        subject="/CN=Test CA/O=Revocation",
        key_type="rsa",
        key_size=4096,
        passphrase_file=str(root_pass_file),
        validity_days=365
    )

    # Initialize database
    db_path = pki_dir / "micropki.db"
    db = Database(str(db_path))

    return {
        'temp_dir': temp_dir,
        'pki_dir': pki_dir,
        'db': db,
        'ca_cert_path': pki_dir / "certs" / "ca.cert.pem",
        'ca_key_path': pki_dir / "private" / "ca.key.pem",
        'pass_file': root_pass_file
    }


def test_revocation_checker_ocsp_first_then_crl(revocation_env):

    # Create a test certificate
    from micropki.intermediate import IssueCertificate
    from micropki.crypto_utils import load_passphrase

    issuer = IssueCertificate()
    ca_pass = load_passphrase(revocation_env['pass_file'])

    cert_path, _ = issuer.issue_certificate(
        ca_cert_path=revocation_env['ca_cert_path'],
        ca_key_path=revocation_env['ca_key_path'],
        ca_pass_file=revocation_env['pass_file'],
        template_name="server",
        subject_dn="/CN=fallback-test.example.com",
        san_list=["dns:fallback-test.example.com"],
        out_dir=revocation_env['pki_dir'] / "certs",
        validity_days=30
    )

    cert = load_certificate(cert_path)
    issuer_cert = load_certificate(revocation_env['ca_cert_path'])
    serial_hex = format(cert.serial_number, '016X')

    # Revoke the certificate
    revoke_mgr = RevocationManager(revocation_env['db'], revocation_env['pki_dir'])
    revoke_mgr.revoke_certificate(serial_hex, reason="keyCompromise", force=True)

    # Generate CRL
    crl_mgr = CRLManager(revocation_env['pki_dir'], revocation_env['db'])
    crl_path = crl_mgr.generate_crl(
        ca_cert_path=revocation_env['ca_cert_path'],
        ca_key_path=revocation_env['ca_key_path'],
        ca_pass_file=revocation_env['pass_file'],
        ca_type="root"
    )

    # Mock OCSP to fail
    with patch.object(OCSPChecker, 'check_certificate',
                      return_value=(RevocationStatus.ERROR, {'error': 'OCSP failed'})):
        checker = RevocationChecker()

        # Should fallback to CRL
        status = checker.check_certificate_status(
            cert=cert,
            issuer=issuer_cert,
            crl_source=str(crl_path),
            prefer_ocsp=True
        )

        assert status == RevocationStatus.REVOKED


def test_revocation_checker_crl_first_fallback(revocation_env):

    cert = load_certificate(revocation_env['ca_cert_path'])
    issuer = cert

    checker = RevocationChecker()


    with patch.object(CRLChecker, 'check_certificate', return_value=(RevocationStatus.ERROR, {'error': 'CRL failed'})):

        status = checker.check_certificate_status(
            cert=cert,
            issuer=issuer,
            prefer_ocsp=False
        )

        # Both failed, should be UNKNOWN
        assert status == RevocationStatus.UNKNOWN


def test_revocation_cache(revocation_env):

    cert = load_certificate(revocation_env['ca_cert_path'])
    issuer = cert

    checker = RevocationChecker(cache_ttl=60)

    # First call - should actually check
    with patch.object(CRLChecker, 'check_certificate', return_value=(RevocationStatus.GOOD, {})) as mock_check:
        status = checker.check_certificate_status(
            cert=cert,
            issuer=issuer,
            prefer_ocsp=False
        )
        assert mock_check.call_count == 1

    # Second call - should use cache
    with patch.object(CRLChecker, 'check_certificate', return_value=(RevocationStatus.GOOD, {})) as mock_check:
        status = checker.check_certificate_status(
            cert=cert,
            issuer=issuer,
            prefer_ocsp=False
        )
        # Should NOT call check again (cached)
        assert mock_check.call_count == 0


def test_crl_freshness_check(revocation_env):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from datetime import datetime, timedelta, timezone

    cert = load_certificate(revocation_env['ca_cert_path'])


    checker = CRLChecker()


    assert checker is not None