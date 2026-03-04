"""Root CA initialization and management."""

from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from . import crypto_utils, certificates, logger


class RootCA:
    """Root Certificate Authority implementation."""

    def __init__(self, out_dir: str, log_file: Optional[str] = None):
        """
        Initialize Root CA.

        Args:
            out_dir: Output directory for CA files
            log_file: Optional log file path
        """
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
        """
        Initialize a new Root CA.

        Args:
            subject: Distinguished Name
            key_type: 'rsa' or 'ecc'
            key_size: Key size in bits
            passphrase_file: Path to passphrase file
            validity_days: Certificate validity in days
        """
        self.logger.info(f"Starting Root CA initialization for subject: {subject}")

        try:
            # Load passphrase
            self.logger.info("Loading passphrase from file")
            passphrase = crypto_utils.load_passphrase(Path(passphrase_file))

            # Generate key pair
            self.logger.info(f"Generating {key_type.upper()} key pair (size: {key_size})")
            if key_type == "rsa":
                private_key = crypto_utils.generate_rsa_key(key_size)
            else:  # ecc
                private_key = crypto_utils.generate_ecc_key(key_size)
            self.logger.info("Key generation completed successfully")

            # Generate serial number
            serial_number = crypto_utils.generate_serial_number()
            self.logger.info(f"Generated serial number: {hex(serial_number)}")

            # Create self-signed certificate
            self.logger.info("Creating self-signed certificate")
            certificate = certificates.create_self_signed_certificate(
                private_key=private_key,
                subject_dn=subject,
                validity_days=validity_days,
                serial_number=serial_number
            )
            self.logger.info("Certificate signing completed successfully")

            # Save encrypted private key
            self.logger.info("Encrypting and saving private key")
            encrypted_key = crypto_utils.encrypt_private_key(private_key, passphrase)
            key_path = self.private_dir / "ca.key.pem"
            crypto_utils.save_private_key(encrypted_key, key_path)
            self.logger.info(f"Private key saved to: {key_path.absolute()}")

            # Save certificate
            self.logger.info("Saving certificate")
            cert_path = self.certs_dir / "ca.cert.pem"
            certificates.save_certificate(certificate, cert_path)
            self.logger.info(f"Certificate saved to: {cert_path.absolute()}")

            # Verify key pair
            self.logger.info("Verifying key pair consistency")
            if not crypto_utils.verify_key_pair(private_key, private_key.public_key()):
                raise RuntimeError("Key pair verification failed")
            self.logger.info("Key pair verification successful")

            # Generate policy document
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

        except Exception as e:
            self.logger.error(f"CA initialization failed: {str(e)}")
            raise

    def _generate_policy_document(
            self,
            subject: str,
            serial_number: int,
            certificate,
            key_type: str,
            key_size: int
    ) -> None:
        # Use UTC methods to avoid deprecation warnings
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc

        policy_content = f"""Certificate Policy Document - MicroPKI Root CA

Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Policy Version: 1.0


CA Name (Subject DN): {subject}
Certificate Serial Number: {hex(serial_number)}
Validity Period:
  Not Before: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}
  Not After:  {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}

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
        """Get SHA-256 fingerprint of certificate."""
        from cryptography.hazmat.primitives import hashes
        fingerprint = certificate.fingerprint(hashes.SHA256())
        return ':'.join(format(b, '02x') for b in fingerprint).upper()