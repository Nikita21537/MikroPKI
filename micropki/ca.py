from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from . import crypto_utils, certificates, logger
from .policy import get_policy, PolicyViolation
from .audit import log_audit_event, init_audit_system
from .transparency import log_certificate_to_ct
from .certificates import compute_certificate_fingerprint


class RootCA:

    def __init__(self, out_dir: str, log_file: Optional[str] = None):
        self.out_dir = Path(out_dir)
        self.private_dir = self.out_dir / "private"
        self.certs_dir = self.out_dir / "certs"
        self.logger = logger.setup_logger(log_file)

    def init_ca(
            self,
            subject: str,
            key_type: str,
            key_size: int,
            passphrase_file: str,
            validity_days: int
    ) -> None:
        self.logger.info(f"Starting Root CA initialization for subject: {subject}")

        # Get policy instance
        policy = get_policy()

        # Validate key size
        is_valid, msg = policy.validate_key_size(key_type, key_size, "root")
        if not is_valid:
            log_audit_event("ca_init", "failure", msg, metadata={"subject": subject})
            raise PolicyViolation(msg)

        # Validate validity period
        is_valid, msg = policy.validate_validity_period(validity_days, "root")
        if not is_valid:
            log_audit_event("ca_init", "failure", msg, metadata={"subject": subject})
            raise PolicyViolation(msg)

        try:
            self.logger.info("Loading passphrase from file")
            passphrase = crypto_utils.load_passphrase(Path(passphrase_file))

            self.logger.info(f"Generating {key_type.upper()} key pair (size: {key_size})")
            if key_type == "rsa":
                private_key = crypto_utils.generate_rsa_key(key_size)
            else:
                private_key = crypto_utils.generate_ecc_key(key_size)
            self.logger.info("Key generation completed successfully")

            serial_number = crypto_utils.generate_serial_number()
            self.logger.info(f"Generated serial number: {hex(serial_number)}")

            self.logger.info("Creating self-signed certificate")
            certificate = certificates.create_self_signed_certificate(
                private_key=private_key,
                subject_dn=subject,
                validity_days=validity_days,
                serial_number=serial_number
            )
            self.logger.info("Certificate signing completed successfully")

            self.logger.info("Encrypting and saving private key")
            encrypted_key = crypto_utils.encrypt_private_key(private_key, passphrase)
            key_path = self.private_dir / "ca.key.pem"
            crypto_utils.save_private_key(encrypted_key, key_path)
            self.logger.info(f"Private key saved to: {key_path.absolute()}")

            self.logger.info("Saving certificate")
            cert_path = self.certs_dir / "ca.cert.pem"
            certificates.save_certificate(certificate, cert_path)
            self.logger.info(f"Certificate saved to: {cert_path.absolute()}")

            self.logger.info("Verifying key pair consistency")
            if not crypto_utils.verify_key_pair(private_key, private_key.public_key()):
                raise RuntimeError("Key pair verification failed")
            self.logger.info("Key pair verification successful")

            # Initialize audit system
            init_audit_system(self.out_dir)

            # CT Logging
            fingerprint = compute_certificate_fingerprint(certificate)
            log_certificate_to_ct(
                serial=format(serial_number, '016X'),
                subject=subject,
                fingerprint=fingerprint,
                issuer=subject  # Self-signed
            )

            # Audit logging
            log_audit_event(
                "ca_init",
                "success",
                f"Root CA initialized with subject {subject}",
                metadata={
                    "subject": subject,
                    "key_type": key_type,
                    "key_size": key_size,
                    "serial": format(serial_number, '016X'),
                    "validity_days": validity_days
                }
            )

            self.logger.info("Generating policy document")
            self._generate_policy_document(
                subject=subject,
                serial_number=serial_number,
                certificate=certificate,
                key_type=key_type,
                key_size=key_size
            )
            self.logger.info(f"Policy document saved to: {(self.out_dir / 'policy.txt').absolute()}")

            self.logger.info("Root CA initialization completed successfully")

        except PolicyViolation:
            raise
        except Exception as e:
            self.logger.error(f"CA initialization failed: {str(e)}")
            log_audit_event("ca_init", "failure", str(e), metadata={"subject": subject})
            raise

    def _generate_policy_document(
            self,
            subject: str,
            serial_number: int,
            certificate,
            key_type: str,
            key_size: int
    ) -> None:
        # Handle timezone-aware vs naive datetimes
        not_before = certificate.not_valid_before_utc if hasattr(certificate, 'not_valid_before_utc') else certificate.not_valid_before
        not_after = certificate.not_valid_after_utc if hasattr(certificate, 'not_valid_after_utc') else certificate.not_valid_after

        policy_content = f"""Certificate Policy Document - MicroPKI Root CA

Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Policy Version: 1.0

CA Information:
--------------
CA Name (Subject DN): {subject}
Certificate Serial Number: {hex(serial_number)}
Validity Period:
  Not Before: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC') if not_before.tzinfo is None else not_before.strftime('%Y-%m-%d %H:%M:%S %Z')}
  Not After:  {not_after.strftime('%Y-%m-%d %H:%M:%S UTC') if not_after.tzinfo is None else not_after.strftime('%Y-%m-%d %H:%M:%S %Z')}

Cryptographic Parameters:
------------------------
Key Algorithm: {key_type.upper()}
Key Size: {key_size} bits
Signature Algorithm: {"SHA-256 with RSA" if key_type == "rsa" else "SHA-384 with ECDSA"}

Certificate Extensions:
----------------------
Basic Constraints: CA=TRUE (Critical)
Key Usage: Certificate Sign, CRL Sign (Critical)
Subject Key Identifier: Included
Authority Key Identifier: Included (self-signed)

Security Policies:
-----------------
- RSA key size minimum: 4096 bits for Root CA
- ECC key size minimum: 384 bits (P-384) for Root CA
- Maximum validity period: 10 years (3650 days)
- Private keys stored encrypted (PKCS#8 with AES-256)
- All operations audited with cryptographic integrity

Purpose:
--------
Root CA for MicroPKI demonstration project.
This CA is intended for educational and testing purposes only.
No warranties or guarantees are provided regarding its security or suitability for production use.

Certificate Fingerprint (SHA-256):
{self._get_certificate_fingerprint(certificate)}

---
End of Policy Document
"""
        policy_path = self.out_dir / "policy.txt"
        with open(policy_path, 'w', encoding='utf-8') as f:
            f.write(policy_content)

    def _get_certificate_fingerprint(self, certificate) -> str:
        from cryptography.hazmat.primitives import hashes
        fingerprint = certificate.fingerprint(hashes.SHA256())
        return ':'.join(format(b, '02x') for b in fingerprint).upper()