"""Certificate chain validation."""

from pathlib import Path
from typing import List, Tuple, Optional
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

from .certificates import load_certificate


class ChainValidator:
    """Certificate chain validator."""

    def __init__(self):
        self.logger = None

    def set_logger(self, logger):
        """Set logger for validation events."""
        self.logger = logger

    def validate_chain(
            self,
            leaf_path: Path,
            intermediate_path: Path,
            root_path: Path
    ) -> Tuple[bool, List[str]]:
        """
        Validate certificate chain.

        Args:
            leaf_path: Path to leaf certificate
            intermediate_path: Path to intermediate CA certificate
            root_path: Path to root CA certificate

        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []

        try:
            # Load certificates
            leaf = load_certificate(leaf_path)
            intermediate = load_certificate(intermediate_path)
            root = load_certificate(root_path)

            # Check validity periods
            self._check_validity(leaf, "Leaf", errors)
            self._check_validity(intermediate, "Intermediate", errors)
            self._check_validity(root, "Root", errors)

            # Check signatures
            self._check_signature(leaf, intermediate.public_key(), "Leaf ← Intermediate", errors)
            self._check_signature(intermediate, root.public_key(), "Intermediate ← Root", errors)

            # Check Basic Constraints
            self._check_basic_constraints(leaf, "Leaf", errors)
            self._check_basic_constraints(intermediate, "Intermediate", errors, expect_ca=True)
            self._check_basic_constraints(root, "Root", errors, expect_ca=True)

            # Check Key Usage
            self._check_key_usage(leaf, "Leaf", errors)
            self._check_key_usage(intermediate, "Intermediate", errors, expect_cert_sign=True)
            self._check_key_usage(root, "Root", errors, expect_cert_sign=True)

            # Check path length constraints
            self._check_path_length(leaf, intermediate, errors)

            return len(errors) == 0, errors

        except Exception as e:
            errors.append(f"Chain validation failed: {str(e)}")
            return False, errors

    def _check_validity(self, cert: x509.Certificate, name: str, errors: List[str]) -> None:
        """Check certificate validity period."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        # Используем обычные атрибуты без _utc
        if now < cert.not_valid_before.replace(tzinfo=None):
            errors.append(f"{name} certificate is not yet valid")

        if now > cert.not_valid_after.replace(tzinfo=None):
            errors.append(f"{name} certificate has expired")

    def _check_signature(
            self,
            cert: x509.Certificate,
            issuer_public_key,
            relationship: str,
            errors: List[str]
    ) -> None:
        """Check certificate signature."""
        try:
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
            else:
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm)
                )
        except Exception as e:
            errors.append(f"Signature verification failed for {relationship}: {str(e)}")

    def _check_basic_constraints(
            self,
            cert: x509.Certificate,
            name: str,
            errors: List[str],
            expect_ca: bool = False
    ) -> None:
        """Check Basic Constraints extension."""
        try:
            bc = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )

            if bc.value.ca != expect_ca:
                errors.append(
                    f"{name} certificate Basic Constraints CA flag is {bc.value.ca}, "
                    f"expected {expect_ca}"
                )
        except x509.extensions.ExtensionNotFound:
            errors.append(f"{name} certificate missing Basic Constraints extension")

    def _check_key_usage(
            self,
            cert: x509.Certificate,
            name: str,
            errors: List[str],
            expect_cert_sign: bool = False
    ) -> None:
        """Check Key Usage extension."""
        try:
            ku = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE
            )

            if expect_cert_sign and not ku.value.key_cert_sign:
                errors.append(f"{name} certificate missing keyCertSign Key Usage")

            # Check that CA certificates have CRL sign
            if expect_cert_sign and not ku.value.crl_sign:
                errors.append(f"{name} certificate missing cRLSign Key Usage")

        except x509.extensions.ExtensionNotFound:
            errors.append(f"{name} certificate missing Key Usage extension")

    def _check_path_length(
            self,
            leaf: x509.Certificate,
            intermediate: x509.Certificate,
            errors: List[str]
    ) -> None:
        """Check path length constraints."""
        try:
            bc = intermediate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )

            pathlen = bc.value.path_length
            if pathlen is not None and pathlen < 0:
                errors.append(f"Intermediate CA has invalid path length: {pathlen}")

        except x509.extensions.ExtensionNotFound:
            # No Basic Constraints on intermediate, already reported
            pass