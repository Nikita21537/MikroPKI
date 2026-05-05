from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, List, Tuple


from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend

from . import crypto_utils, certificates
from . import csr as csr_module
from . import templates
from .logger import setup_logger
from .database import Database
from .policy import get_policy, PolicyViolation
from .audit import log_audit_event
from .transparency import log_certificate_to_ct
from .compromise import CompromiseManager, CompromiseChecker
from .certificates import compute_certificate_fingerprint


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

        # Get policy for validation
        policy = get_policy()

        # Validate policy for intermediate CA
        is_valid, msg = policy.validate_validity_period(validity_days, "intermediate")
        if not is_valid:
            log_audit_event("issue_intermediate", "failure", msg, metadata={"subject": subject_dn})
            raise PolicyViolation(msg)

        is_valid, msg = policy.validate_path_length(pathlen, is_intermediate=True)
        if not is_valid:
            log_audit_event("issue_intermediate", "failure", msg, metadata={"subject": subject_dn})
            raise PolicyViolation(msg)

        try:
            self.logger.info("Loading Root CA certificate and key")
            root_cert = certificates.load_certificate(root_cert_path)
            root_pass = crypto_utils.load_passphrase(root_pass_file)
            root_key = crypto_utils.load_encrypted_private_key(root_key_path, root_pass)

            self.logger.info(f"Generating {key_type.upper()} key pair for Intermediate CA")
            if key_type == "rsa":
                # Validate key size
                is_valid, msg = policy.validate_key_size("rsa", 4096, "intermediate")
                if not is_valid:
                    raise PolicyViolation(msg)
                inter_key = crypto_utils.generate_rsa_key(4096)
            else:
                is_valid, msg = policy.validate_key_size("ecc", 384, "intermediate")
                if not is_valid:
                    raise PolicyViolation(msg)
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

            # Insert into database
            db_path = self.out_dir / "micropki.db"
            if db_path.exists():
                try:
                    db = Database(str(db_path))
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
                except Exception as e:
                    self.logger.warning(f"Database insertion skipped: {e}")

            # CT logging
            fingerprint = compute_certificate_fingerprint(inter_cert)
            log_certificate_to_ct(
                serial=format(serial_number, '016X'),
                subject=subject_dn,
                fingerprint=fingerprint,
                issuer=root_cert.subject.rfc4514_string()
            )

            # Audit logging
            log_audit_event(
                "issue_intermediate",
                "success",
                f"Intermediate CA issued with subject {subject_dn}",
                metadata={
                    "serial": format(serial_number, '016X'),
                    "subject": subject_dn,
                    "pathlen": pathlen,
                    "validity_days": validity_days
                }
            )

            # Update policy document
            self._update_policy_document(
                subject=subject_dn,
                serial_number=serial_number,
                certificate=inter_cert,
                issuer_cert=root_cert,
                key_type=key_type,
                pathlen=pathlen
            )

            self.logger.info("Intermediate CA creation completed successfully")

        except PolicyViolation:
            raise
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

        # Basic Constraints: CA=TRUE with path length
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=pathlen),
            critical=True
        )

        # Key Usage: keyCertSign, cRLSign
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

        # Subject Key Identifier
        ski = x509.SubjectKeyIdentifier.from_public_key(csr.public_key())
        builder = builder.add_extension(ski, critical=False)

        # Authority Key Identifier
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())
        builder = builder.add_extension(aki, critical=False)

        # Sign the certificate
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
  Not Before: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC') if not_before.tzinfo is None else not_before.strftime('%Y-%m-%d %H:%M:%S %Z')}
  Not After:  {not_after.strftime('%Y-%m-%d %H:%M:%S UTC') if not_after.tzinfo is None else not_after.strftime('%Y-%m-%d %H:%M:%S %Z')}
Key Algorithm: {key_type.upper()}
Path Length Constraint: {pathlen}
Certificate Extensions:
  Basic Constraints: CA=TRUE, PathLen={pathlen} (Critical)
  Key Usage: Certificate Sign, CRL Sign (Critical)

--- End of Intermediate CA Section ---
"""

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

        self.logger.info(f"Issuing {template_name} certificate")

        # Get policy instance
        policy = get_policy()

        # Validate validity period
        is_valid, msg = policy.validate_validity_period(validity_days, "end_entity")
        if not is_valid:
            log_audit_event("issue_certificate", "failure", msg, metadata={"subject": subject_dn})
            raise PolicyViolation(msg)

        # Initialize database for compromise checking
        db_path = out_dir.parent / "micropki.db"
        db = None
        if db_path.exists():
            db = Database(str(db_path))

        try:
            ca_cert = certificates.load_certificate(ca_cert_path)
            ca_pass = crypto_utils.load_passphrase(ca_pass_file)
            ca_key = crypto_utils.load_encrypted_private_key(ca_key_path, ca_pass)

            # Variables to be set based on CSR or new key generation
            public_key = None
            private_key = None
            final_subject_dn = subject_dn
            final_san_list = san_list.copy() if san_list else []

            if csr_path and csr_path.exists():
                # Load and verify CSR
                self.logger.info(f"Loading CSR from {csr_path}")
                csr_obj = csr_module.load_csr(csr_path)

                if not csr_module.verify_csr(csr_obj):
                    raise ValueError("CSR signature verification failed")

                public_key = csr_obj.public_key()
                private_key = None

                # POLICY CHECK: Key size from CSR
                from cryptography.hazmat.primitives.asymmetric import rsa, ec
                if isinstance(public_key, rsa.RSAPublicKey):
                    key_size = public_key.key_size
                    is_valid, msg = policy.validate_key_size("rsa", key_size, "end_entity")
                    if not is_valid:
                        log_audit_event("issue_certificate", "failure", msg, metadata={"csr": str(csr_path)})
                        raise PolicyViolation(msg)
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_size = public_key.curve.key_size
                    is_valid, msg = policy.validate_key_size("ecc", key_size, "end_entity")
                    if not is_valid:
                        log_audit_event("issue_certificate", "failure", msg, metadata={"csr": str(csr_path)})
                        raise PolicyViolation(msg)

                # POLICY CHECK: Compromised key
                if db:
                    compromise_mgr = CompromiseManager(db, out_dir.parent)
                    checker = CompromiseChecker(compromise_mgr)
                    is_valid, msg = checker.check_csr_for_compromise(public_key)
                    if not is_valid:
                        log_audit_event("issue_certificate", "failure", msg, metadata={"csr": str(csr_path)})
                        raise PolicyViolation(msg)

                # Extract subject from CSR
                final_subject_dn = csr_obj.subject.rfc4514_string()
                self.logger.info(f"Using subject from CSR: {final_subject_dn}")

                # Extract SANs from CSR if present
                csr_sans = self._extract_sans_from_csr(csr_obj)
                if csr_sans:
                    final_san_list = csr_sans
                    self.logger.info(f"Using SANs from CSR: {final_san_list}")

                # POLICY CHECK: SAN validation
                if final_san_list:
                    is_valid, msg = policy.validate_san_list(final_san_list, template_name)
                    if not is_valid:
                        log_audit_event("issue_certificate", "failure", msg, metadata={"csr": str(csr_path)})
                        raise PolicyViolation(msg)

                # Validate CSR extensions against template
                self._validate_csr_against_template(csr_obj, template_name)

            else:
                # Generate new key pair
                self.logger.info("Generating new key pair")
                if isinstance(ca_key, rsa.RSAPrivateKey):
                    # Validate key size
                    is_valid, msg = policy.validate_key_size("rsa", 2048, "end_entity")
                    if not is_valid:
                        raise PolicyViolation(msg)
                    private_key = crypto_utils.generate_rsa_key(2048)
                else:
                    is_valid, msg = policy.validate_key_size("ecc", 256, "end_entity")
                    if not is_valid:
                        raise PolicyViolation(msg)
                    private_key = crypto_utils.generate_ecc_key(256)
                public_key = private_key.public_key()

                if not subject_dn:
                    raise ValueError("subject_dn is required when not using CSR")

                self.logger.info(f"Using subject: {subject_dn}")
                if san_list:
                    self.logger.info(f"Using SANs: {san_list}")

            # POLICY CHECK: SAN validation for non-CSR path
            if final_san_list and not csr_path:
                is_valid, msg = policy.validate_san_list(final_san_list, template_name)
                if not is_valid:
                    log_audit_event("issue_certificate", "failure", msg, metadata={"subject": final_subject_dn})
                    raise PolicyViolation(msg)

            # Build certificate
            certificate = self._build_certificate(
                public_key=public_key,
                subject_dn=final_subject_dn,
                issuer_cert=ca_cert,
                issuer_key=ca_key,
                template_name=template_name,
                san_list=final_san_list,
                validity_days=validity_days
            )

            # Determine output filenames
            subject = certificates.parse_dn_string(final_subject_dn)
            common_name = None
            for attr in subject:
                if attr.oid == NameOID.COMMON_NAME:
                    common_name = attr.value
                    break

            if not common_name:
                common_name = "cert"

            filename = common_name.replace(' ', '_').replace('/', '_').replace('*', 'wildcard')

            # Save certificate
            out_dir.mkdir(parents=True, exist_ok=True)
            cert_path = out_dir / f"{filename}.cert.pem"
            certificates.save_certificate(certificate, cert_path)

            # Save private key if generated (not from CSR)
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
                self.logger.info(f"Private key saved to: {key_path}")

            # Insert into database
            if db_path.exists():
                try:
                    if db is None:
                        db = Database(str(db_path))

                    serial_hex = format(certificate.serial_number, '016X')

                    cert_data = {
                        'serial_hex': serial_hex,
                        'subject': final_subject_dn,
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

            # CT Logging
            fingerprint = compute_certificate_fingerprint(certificate)
            log_certificate_to_ct(
                serial=format(certificate.serial_number, '016X'),
                subject=final_subject_dn,
                fingerprint=fingerprint,
                issuer=ca_cert.subject.rfc4514_string()
            )

            # Audit logging
            log_audit_event(
                "issue_certificate",
                "success",
                f"Issued {template_name} certificate for {final_subject_dn}",
                metadata={
                    "serial": format(certificate.serial_number, '016X'),
                    "subject": final_subject_dn,
                    "template": template_name,
                    "validity_days": validity_days,
                    "from_csr": bool(csr_path)
                }
            )

            self.logger.info(f"Certificate issued: serial={hex(certificate.serial_number)}, "
                             f"template={template_name}, subject={final_subject_dn}")

            return cert_path, key_path

        except PolicyViolation:
            raise
        except Exception as e:
            self.logger.error(f"Certificate issuance failed: {str(e)}")
            raise

    def _validate_csr_against_template(self, csr: x509.CertificateSigningRequest, template_name: str) -> None:

        template = templates.get_template(template_name)

        # Check if CSR requests CA certificate
        try:
            from cryptography.x509.oid import ExtensionOID
            for ext in csr.extensions:
                if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                    if ext.value.ca:
                        raise ValueError(f"CSR requests CA certificate but template {template_name} is for end-entity")
                    break
        except x509.extensions.ExtensionNotFound:
            pass  # No Basic Constraints, which is fine for end-entity

        # Extract SANs for validation
        san_list = self._extract_sans_from_csr(csr)
        if san_list:
            try:
                template.validate_sans(san_list)
                self.logger.info(f"CSR SANs validated against {template_name} template")
            except ValueError as e:
                raise ValueError(f"CSR SANs invalid for {template_name} template: {e}")

    def _extract_sans_from_csr(self, csr: x509.CertificateSigningRequest) -> List[str]:

        san_list = []
        try:
            from cryptography.x509.oid import ExtensionOID
            for ext in csr.extensions:
                if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    for san in ext.value:
                        if isinstance(san, x509.DNSName):
                            san_list.append(f"dns:{san.value}")
                        elif isinstance(san, x509.IPAddress):
                            san_list.append(f"ip:{san.value}")
                        elif isinstance(san, x509.RFC822Name):
                            san_list.append(f"email:{san.value}")
                        elif isinstance(san, x509.UniformResourceIdentifier):
                            san_list.append(f"uri:{san.value}")
                    break
        except Exception as e:
            self.logger.warning(f"Failed to extract SANs from CSR: {e}")

        return san_list

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

        from .templates import get_template, build_san_extension

        subject = certificates.parse_dn_string(subject_dn)
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

        # Add template extensions
        builder = builder.add_extension(template.get_basic_constraints(), critical=True)
        builder = builder.add_extension(template.get_key_usage(), critical=True)
        builder = builder.add_extension(template.get_extended_key_usage(), critical=False)

        # Add SAN extension if provided
        if san_list:
            san_ext = build_san_extension(san_list, template_name)
            builder = builder.add_extension(san_ext, critical=False)

        # Add SKI
        ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(ski, critical=False)

        # Add AKI
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())
        builder = builder.add_extension(aki, critical=False)

        # Sign the certificate
        if isinstance(issuer_key, rsa.RSAPrivateKey):
            certificate = builder.sign(issuer_key, hashes.SHA256(), default_backend())
        else:
            certificate = builder.sign(issuer_key, hashes.SHA384(), default_backend())

        return certificate