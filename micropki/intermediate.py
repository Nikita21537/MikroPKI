from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, List, Tuple


from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend

from . import crypto_utils, certificates, csr as csr_module, templates
from .logger import setup_logger
from .database import Database


class IntermediateCA:

    def __init__(self, out_dir: str, log_file: Optional[str] = None):
        self.out_dir = Path(out_dir)
        self.private_dir = self.out_dir / "private"
        self.certs_dir = self.out_dir / "certs"
        self.csrs_dir = self.out_dir / "csrs"
        self.logger = setup_logger(log_file)

    def create_intermediate_ca(
            self,
            root_cert_path: Path,
            root_key_path: Path,
            root_pass_file: Path,
            subject_dn: str,
            key_type: str,
            passphrase_file: Path,
            validity_days: int,
            pathlen: int
    ) -> None:
        self.logger.info(f"Creating Intermediate CA with subject: {subject_dn}")

        try:
            self.logger.info("Loading Root CA certificate and key")
            root_cert = certificates.load_certificate(root_cert_path)
            root_pass = crypto_utils.load_passphrase(root_pass_file)
            root_key = crypto_utils.load_encrypted_private_key(root_key_path, root_pass)

            self.logger.info(f"Generating {key_type.upper()} key pair for Intermediate CA")
            if key_type == "rsa":
                inter_key = crypto_utils.generate_rsa_key(4096)
            else:
                inter_key = crypto_utils.generate_ecc_key(384)

            self.logger.info("Generating CSR for Intermediate CA")
            inter_csr = csr_module.generate_csr(
                private_key=inter_key,
                subject_dn=subject_dn,
                template_name="server",
                san_list=None,
                pathlen=pathlen
            )

            csr_path = self.csrs_dir / "intermediate.csr.pem"
            csr_module.save_csr(inter_csr, csr_path)
            self.logger.info(f"CSR saved to: {csr_path.absolute()}")

            self.logger.info("Signing Intermediate CSR with Root CA")
            inter_cert, serial_number = self._sign_intermediate_certificate(
                csr=inter_csr,
                issuer_cert=root_cert,
                issuer_key=root_key,
                validity_days=validity_days,
                pathlen=pathlen
            )

            self.logger.info(f"Generated serial number: {hex(serial_number)}")

            self.logger.info("Encrypting and saving Intermediate CA private key")
            inter_pass = crypto_utils.load_passphrase(passphrase_file)
            encrypted_key = crypto_utils.encrypt_private_key(inter_key, inter_pass)
            key_path = self.private_dir / "intermediate.key.pem"
            crypto_utils.save_private_key(encrypted_key, key_path)
            self.logger.info(f"Private key saved to: {key_path.absolute()}")

            self.logger.info("Saving Intermediate CA certificate")
            cert_path = self.certs_dir / "intermediate.cert.pem"
            certificates.save_certificate(inter_cert, cert_path)
            self.logger.info(f"Certificate saved to: {cert_path.absolute()}")

            # Вставка в базу данных
            db_path = self.out_dir / "micropki.db"
            if db_path.exists():
                try:
                    db = Database(str(db_path))

                    # Конвертируем serial_number в hex строку
                    serial_hex = format(serial_number, '016X')

                    cert_data = {
                        'serial_hex': serial_hex,
                        'subject': subject_dn,
                        'issuer': root_cert.subject.rfc4514_string(),
                        'not_before': inter_cert.not_valid_before.isoformat(),
                        'not_after': inter_cert.not_valid_after.isoformat(),
                        'cert_pem': inter_cert.public_bytes(serialization.Encoding.PEM).decode(),
                        'status': 'valid',
                        'created_at': datetime.utcnow().isoformat()
                    }

                    if db.insert_certificate(cert_data):
                        self.logger.info(f"Intermediate CA inserted into database: {serial_hex}")
                    else:
                        self.logger.warning("Failed to insert Intermediate CA into database")
                except Exception as e:
                    self.logger.warning(f"Database insertion skipped: {e}")

            self.logger.info("Updating policy document")
            self._update_policy_document(
                subject=subject_dn,
                serial_number=serial_number,
                certificate=inter_cert,
                issuer_cert=root_cert,
                key_type=key_type,
                pathlen=pathlen
            )

            self.logger.info("Intermediate CA creation completed successfully")

        except Exception as e:
            self.logger.error(f"Intermediate CA creation failed: {str(e)}")
            raise

    def _sign_intermediate_certificate(
            self,
            csr: x509.CertificateSigningRequest,
            issuer_cert: x509.Certificate,
            issuer_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
            validity_days: int,
            pathlen: int
    ) -> Tuple[x509.Certificate, int]:
        serial_number = crypto_utils.generate_serial_number()

        not_valid_before = datetime.now(timezone.utc).replace(tzinfo=None)
        not_valid_after = not_valid_before + timedelta(days=validity_days)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)
        builder = builder.serial_number(serial_number)
        builder = builder.public_key(csr.public_key())

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=pathlen),
            critical=True
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        ski = x509.SubjectKeyIdentifier.from_public_key(csr.public_key())
        builder = builder.add_extension(ski, critical=False)

        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())
        builder = builder.add_extension(aki, critical=False)

        if isinstance(issuer_key, rsa.RSAPrivateKey):
            certificate = builder.sign(issuer_key, hashes.SHA256(), default_backend())
        else:
            certificate = builder.sign(issuer_key, hashes.SHA384(), default_backend())

        return certificate, serial_number

    def _update_policy_document(
            self,
            subject: str,
            serial_number: int,
            certificate: x509.Certificate,
            issuer_cert: x509.Certificate,
            key_type: str,
            pathlen: int
    ) -> None:

        policy_path = self.out_dir / "policy.txt"

        not_before = certificate.not_valid_before
        not_after = certificate.not_valid_after

        policy_entry = f"""
Intermediate CA Information:
---------------------------
CA Name (Subject DN): {subject}
Serial Number: {hex(serial_number)}
Issuer: {issuer_cert.subject.rfc4514_string()}
Validity Period:
  Not Before: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}
  Not After:  {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}
Key Algorithm: {key_type.upper()}
Path Length Constraint: {pathlen}
Certificate Extensions:
  Basic Constraints: CA=TRUE, PathLen={pathlen} (Critical)
  Key Usage: Certificate Sign, CRL Sign (Critical)

--- End of Intermediate CA Section ---
"""

        # Append to existing policy file or create new
        mode = 'a' if policy_path.exists() else 'w'
        with open(policy_path, mode, encoding='utf-8') as f:
            f.write(policy_entry)


class IssueCertificate:

    def __init__(self, log_file: Optional[str] = None):
        self.logger = setup_logger(log_file)

    def issue_certificate(
            self,
            ca_cert_path: Path,
            ca_key_path: Path,
            ca_pass_file: Path,
            template_name: str,
            subject_dn: str,
            san_list: List[str],
            out_dir: Path,
            validity_days: int,
            csr_path: Optional[Path] = None
    ) -> Tuple[Path, Optional[Path]]:
        self.logger.info(f"Issuing {template_name} certificate for subject: {subject_dn}")

        try:
            ca_cert = certificates.load_certificate(ca_cert_path)
            ca_pass = crypto_utils.load_passphrase(ca_pass_file)
            ca_key = crypto_utils.load_encrypted_private_key(ca_key_path, ca_pass)

            if csr_path:
                self.logger.info(f"Loading CSR from {csr_path}")
                csr_obj = csr_module.load_csr(csr_path)

                if not csr_module.verify_csr(csr_obj):
                    raise ValueError("CSR signature verification failed")

                public_key = csr_obj.public_key()
                private_key = None
                csr_info = csr_module.extract_csr_info(csr_obj)
                self.logger.info(f"CSR loaded: {csr_info}")
            else:
                self.logger.info("Generating new key pair")

                if isinstance(ca_key, rsa.RSAPrivateKey):
                    private_key = crypto_utils.generate_rsa_key(2048)
                else:
                    private_key = crypto_utils.generate_ecc_key(256)
                public_key = private_key.public_key()

            certificate = self._build_certificate(
                public_key=public_key,
                subject_dn=subject_dn,
                issuer_cert=ca_cert,
                issuer_key=ca_key,
                template_name=template_name,
                san_list=san_list,
                validity_days=validity_days
            )

            from .certificates import parse_dn_string
            subject = parse_dn_string(subject_dn)
            common_name = None
            for attr in subject:
                if attr.oid == NameOID.COMMON_NAME:
                    common_name = attr.value
                    break

            if not common_name:
                common_name = "cert"

            filename = common_name.replace(' ', '_').replace('/', '_')

            cert_path = out_dir / f"{filename}.cert.pem"
            certificates.save_certificate(certificate, cert_path)

            key_path = None
            if private_key:
                key_path = out_dir / f"{filename}.key.pem"
                unencrypted_key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                with open(key_path, 'wb') as f:
                    f.write(unencrypted_key)
                import os
                try:
                    os.chmod(key_path, 0o600)
                except Exception:
                    pass

            # Вставка в базу данных
            db_path = out_dir.parent / "micropki.db"  # pki/micropki.db
            if not db_path.exists():
                db_path = out_dir / "micropki.db"

            if db_path.exists():
                try:
                    from .database import Database
                    db = Database(str(db_path))

                    serial_hex = format(certificate.serial_number, '016X')

                    cert_data = {
                        'serial_hex': serial_hex,
                        'subject': subject_dn,
                        'issuer': ca_cert.subject.rfc4514_string(),
                        'not_before': certificate.not_valid_before.isoformat(),
                        'not_after': certificate.not_valid_after.isoformat(),
                        'cert_pem': certificate.public_bytes(serialization.Encoding.PEM).decode(),
                        'status': 'valid',
                        'created_at': datetime.utcnow().isoformat()
                    }

                    if db.insert_certificate(cert_data):
                        self.logger.info(f"Certificate inserted into database: {serial_hex}")
                    else:
                        self.logger.warning("Failed to insert certificate into database")
                except Exception as e:
                    self.logger.warning(f"Database insertion skipped: {e}")

            self.logger.info(f"Certificate issued: serial={hex(certificate.serial_number)}, "
                             f"template={template_name}, subject={subject_dn}, sans={san_list}")

            return cert_path, key_path

        except Exception as e:
            self.logger.error(f"Certificate issuance failed: {str(e)}")
            raise

    def _build_certificate(
            self,
            public_key,
            subject_dn: str,
            issuer_cert: x509.Certificate,
            issuer_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
            template_name: str,
            san_list: List[str],
            validity_days: int
    ) -> x509.Certificate:
        from .certificates import parse_dn_string
        from .templates import get_template

        subject = parse_dn_string(subject_dn)
        template = get_template(template_name)

        serial_number = crypto_utils.generate_serial_number()

        not_valid_before = datetime.now(timezone.utc).replace(tzinfo=None)
        not_valid_after = not_valid_before + timedelta(days=validity_days)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)
        builder = builder.serial_number(serial_number)
        builder = builder.public_key(public_key)

        builder = builder.add_extension(template.get_basic_constraints(), critical=True)
        builder = builder.add_extension(template.get_key_usage(), critical=True)
        builder = builder.add_extension(template.get_extended_key_usage(), critical=False)

        if san_list:
            san_ext = templates.build_san_extension(san_list, template_name)
            builder = builder.add_extension(san_ext, critical=False)

        ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(ski, critical=False)

        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())
        builder = builder.add_extension(aki, critical=False)

        if isinstance(issuer_key, rsa.RSAPrivateKey):
            certificate = builder.sign(issuer_key, hashes.SHA256(), default_backend())
        else:
            certificate = builder.sign(issuer_key, hashes.SHA384(), default_backend())

        return certificate