import pytest
import tempfile
import time
import shutil
from pathlib import Path
from datetime import datetime, timezone


from micropki.ca import RootCA
from micropki.intermediate import IssueCertificate
from micropki.database import Database
from micropki.certificates import load_certificate


@pytest.mark.perf
@pytest.mark.slow
def test_issue_1000_certificates_performance():

    temp_dir = Path(tempfile.mkdtemp())
    pki_dir = temp_dir / "pki"
    secrets_dir = temp_dir / "secrets"

    pki_dir.mkdir()
    secrets_dir.mkdir()

    try:

        root_pass_file = secrets_dir / "root.pass"
        root_pass_file.write_text("testpass123\n")

        root_ca = RootCA(str(pki_dir))
        root_ca.init_ca(
            subject="/CN=Performance Test CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=str(root_pass_file),
            validity_days=365
        )


        db = Database(str(pki_dir / "micropki.db"))

        issuer = IssueCertificate()
        ca_cert_path = pki_dir / "certs" / "ca.cert.pem"
        ca_key_path = pki_dir / "private" / "ca.key.pem"


        start_time = time.time()
        cert_paths = []

        for i in range(1000):
            subject = f"/CN=test{i:04d}.example.com"
            cert_path, _ = issuer.issue_certificate(
                ca_cert_path=ca_cert_path,
                ca_key_path=ca_key_path,
                ca_pass_file=root_pass_file,
                template_name="server",
                subject_dn=subject,
                san_list=[f"dns:test{i:04d}.example.com"],
                out_dir=pki_dir / "certs",
                validity_days=30
            )
            cert_paths.append(cert_path)

        issuance_time = time.time() - start_time


        start_validation = time.time()
        for cert_path in cert_paths:
            cert = load_certificate(cert_path)
            assert cert is not None
        validation_time = time.time() - start_validation


        all_certs = db.list_certificates(limit=2000)
        assert len(all_certs) >= 1000


        print(f"\n{'=' * 60}")
        print(f"PERFORMANCE TEST RESULTS")
        print(f"{'=' * 60}")
        print(f"Certificates issued: 1000")
        print(f"Issuance time: {issuance_time:.2f} seconds")
        print(f"Rate: {1000 / issuance_time:.1f} certificates/second")
        print(f"Validation time: {validation_time:.2f} seconds")
        print(f"Rate: {1000 / validation_time:.1f} validations/second")
        print(f"{'=' * 60}\n")


        assert issuance_time < 60, f"Issuance took {issuance_time:.2f}s, expected <60s"
        assert validation_time < 30, f"Validation took {validation_time:.2f}s, expected <30s"

    finally:
        shutil.rmtree(temp_dir)


@pytest.mark.perf
def test_crl_with_1000_revoked_certificates():
    import tempfile
    from micropki.revocation import RevocationManager, CRLManager
    from micropki.crypto_utils import generate_rsa_key, generate_serial_number
    from micropki.certificates import create_self_signed_certificate, save_certificate

    temp_dir = Path(tempfile.mkdtemp())
    pki_dir = temp_dir / "pki"
    secrets_dir = temp_dir / "secrets"

    pki_dir.mkdir()
    pki_dir.joinpath("certs").mkdir()
    pki_dir.joinpath("private").mkdir()
    secrets_dir.mkdir()

    try:

        root_pass_file = secrets_dir / "root.pass"
        root_pass_file.write_text("testpass\n")

        root_ca = RootCA(str(pki_dir))
        root_ca.init_ca(
            subject="/CN=CRL Test CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=str(root_pass_file),
            validity_days=365
        )

        db = Database(str(pki_dir / "micropki.db"))


        issuer = IssueCertificate()
        ca_cert_path = pki_dir / "certs" / "ca.cert.pem"
        ca_key_path = pki_dir / "private" / "ca.key.pem"

        cert_paths = []
        for i in range(1000):
            cert_path, _ = issuer.issue_certificate(
                ca_cert_path=ca_cert_path,
                ca_key_path=ca_key_path,
                ca_pass_file=root_pass_file,
                template_name="client",
                subject_dn=f"/CN=user{i:04d}",
                san_list=[f"email:user{i:04d}@test.com"],
                out_dir=pki_dir / "certs",
                validity_days=30
            )
            cert_paths.append(cert_path)


        revoke_mgr = RevocationManager(db, pki_dir)
        for cert_path in cert_paths[:100]:
            cert = load_certificate(cert_path)
            serial = format(cert.serial_number, '016X')
            revoke_mgr.revoke_certificate(serial, reason="keyCompromise", force=True)


        crl_mgr = CRLManager(pki_dir, db)

        start_time = time.time()
        crl_path = crl_mgr.generate_crl(
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            ca_pass_file=root_pass_file,
            ca_type="root"
        )
        crl_time = time.time() - start_time

        print(f"\nCRL Generation with 100 revoked certs: {crl_time:.2f} seconds")
        assert crl_time < 10, f"CRL generation took {crl_time:.2f}s, expected <10s"
        assert crl_path.exists()

    finally:
        shutil.rmtree(temp_dir)