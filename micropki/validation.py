from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtendedKeyUsageOID


class ValidationStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class StepResult:
    name: str
    status: ValidationStatus
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CertificateValidationResult:
    certificate: x509.Certificate
    subject: str
    issuer: str
    serial: str
    steps: List[StepResult] = field(default_factory=list)
    is_valid: bool = True

    def add_step(self, name: str, status: ValidationStatus, message: str = "", **kwargs):
        self.steps.append(StepResult(name, status, message, kwargs))
        if status == ValidationStatus.FAIL:
            self.is_valid = False


@dataclass
class ChainValidationResult:
    leaf_subject: str
    validation_time: datetime
    chain: List[CertificateValidationResult] = field(default_factory=list)
    revocation_status: Optional[str] = None
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'leaf_subject': self.leaf_subject,
            'validation_time': self.validation_time.isoformat(),
            'is_valid': self.is_valid,
            'errors': self.errors,
            'chain': [
                {
                    'subject': cert.subject,
                    'issuer': cert.issuer,
                    'serial': cert.serial,
                    'is_valid': cert.is_valid,
                    'steps': [
                        {'name': s.name, 'status': s.status.value, 'message': s.message}
                        for s in cert.steps
                    ]
                }
                for cert in self.chain
            ],
            'revocation_status': self.revocation_status
        }


class ChainBuilder:


    def __init__(self, trusted_roots: List[x509.Certificate]):
        self.trusted_roots = {self._get_normalized_subject(root): root for root in trusted_roots}

    def _get_normalized_subject(self, cert: x509.Certificate) -> str:
        """Get normalized subject DN for matching."""
        return cert.subject.rfc4514_string().lower()

    def _get_normalized_issuer(self, cert: x509.Certificate) -> str:
        """Get normalized issuer DN for matching."""
        return cert.issuer.rfc4514_string().lower()

    def build_chain(
        self,
        leaf: x509.Certificate,
        intermediates: List[x509.Certificate]
    ) -> Optional[List[x509.Certificate]]:

        # Create lookup by subject (case-insensitive)
        intermediates_by_subject = {}
        for cert in intermediates:
            subject = self._get_normalized_subject(cert)
            if subject not in intermediates_by_subject:
                intermediates_by_subject[subject] = cert

        chain = [leaf]
        current = leaf
        max_depth = 10
        depth = 0

        while depth < max_depth:
            issuer_name = self._get_normalized_issuer(current)
            subject_name = self._get_normalized_subject(current)

            # Check if current is self-signed (issuer == subject)
            if issuer_name == subject_name:
                # Look for matching trusted root
                for root_subject, root_cert in self.trusted_roots.items():
                    if root_subject == issuer_name:
                        chain.append(root_cert)
                        return chain
                # Self-signed but not in trusted roots
                return None

            # Try to find issuer in intermediates
            if issuer_name in intermediates_by_subject:
                issuer = intermediates_by_subject[issuer_name]
                # Check that we don't have a cycle
                if issuer in chain:
                    return None
                chain.append(issuer)
                current = issuer
                depth += 1
                continue

            # Try to find issuer in trusted roots
            if issuer_name in self.trusted_roots:
                chain.append(self.trusted_roots[issuer_name])
                return chain

            # No issuer found
            return None

        return None


class PathValidator:


    def __init__(self, validation_time: Optional[datetime] = None):
        if validation_time:
            self.validation_time = validation_time
            if hasattr(self.validation_time, 'tzinfo') and self.validation_time.tzinfo is not None:
                self.validation_time = self.validation_time.replace(tzinfo=None)
        else:
            self.validation_time = datetime.now(timezone.utc).replace(tzinfo=None)

    def validate_chain(
        self,
        leaf: x509.Certificate,
        intermediates: List[x509.Certificate],
        trusted_roots: List[x509.Certificate],
        check_revocation: bool = False,
        revocation_checker = None,
        intended_usage: Optional[str] = None
    ) -> ChainValidationResult:

        result = ChainValidationResult(
            leaf_subject=leaf.subject.rfc4514_string(),
            validation_time=self.validation_time
        )

        # Step 1: Build chain
        builder = ChainBuilder(trusted_roots)
        chain = builder.build_chain(leaf, intermediates)

        if chain is None:
            result.is_valid = False
            result.errors.append("Failed to build certificate chain")
            return result

        # Step 2: Validate each certificate in the chain (excluding root)
        for i in range(len(chain) - 1):
            cert = chain[i]
            issuer = chain[i + 1]
            is_ca = (i < len(chain) - 2)  # Certificates before the last are CAs

            cert_result = self._validate_certificate(cert, issuer, is_ca, intended_usage)
            result.chain.append(cert_result)

            if not cert_result.is_valid:
                result.is_valid = False

        # Step 3: Check revocation if requested and chain is valid
        if check_revocation and result.is_valid and revocation_checker and len(chain) > 1:
            leaf_issuer = chain[1]
            try:
                from .revocation_check import RevocationStatus
                rev_status = revocation_checker.check_certificate_status(leaf, leaf_issuer)
                if hasattr(rev_status, 'value'):
                    result.revocation_status = rev_status.value
                else:
                    result.revocation_status = str(rev_status)

                if rev_status == RevocationStatus.REVOKED or (hasattr(rev_status, 'value') and rev_status.value == "revoked"):
                    result.is_valid = False
                    result.errors.append("Certificate is revoked")
            except ImportError:
                pass

        return result

    def _validate_certificate(
        self,
        cert: x509.Certificate,
        issuer: x509.Certificate,
        is_ca: bool,
        intended_usage: Optional[str] = None
    ) -> CertificateValidationResult:

        result = CertificateValidationResult(
            certificate=cert,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial=format(cert.serial_number, '016X')
        )

        self._check_signature(cert, issuer, result)
        self._check_validity_period(cert, result)
        self._check_basic_constraints(cert, is_ca, result)
        self._check_key_usage(cert, is_ca, result)

        if intended_usage:
            self._check_extended_key_usage(cert, intended_usage, result)

        return result

    def _check_signature(self, cert: x509.Certificate, issuer: x509.Certificate, result: CertificateValidationResult):

        try:
            issuer_public_key = issuer.public_key()

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
            result.add_step("Signature Verification", ValidationStatus.PASS, "Signature is valid")
        except Exception as e:
            result.add_step("Signature Verification", ValidationStatus.FAIL, f"Invalid signature: {e}")

    def _check_validity_period(self, cert: x509.Certificate, result: CertificateValidationResult):

        not_before = cert.not_valid_before
        not_after = cert.not_valid_after

        # Normalize timezone for comparison
        if hasattr(not_before, 'tzinfo') and not_before.tzinfo is not None:
            not_before = not_before.replace(tzinfo=None)
        if hasattr(not_after, 'tzinfo') and not_after.tzinfo is not None:
            not_after = not_after.replace(tzinfo=None)

        if self.validation_time < not_before:
            result.add_step(
                "Validity Period", ValidationStatus.FAIL,
                f"Certificate not yet valid (valid from {not_before})"
            )
        elif self.validation_time > not_after:
            result.add_step(
                "Validity Period", ValidationStatus.FAIL,
                f"Certificate expired on {not_after}"
            )
        else:
            result.add_step(
                "Validity Period", ValidationStatus.PASS,
                f"Valid from {not_before} to {not_after}"
            )

    def _check_basic_constraints(self, cert: x509.Certificate, is_ca: bool, result: CertificateValidationResult):

        try:
            bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
            is_ca_in_cert = bc.value.ca

            # CORRECTED LOGIC:
            # For CA certificates: is_ca=True (we are validating it as a CA)
            # For end-entity certificates: is_ca=False
            if is_ca:
                # This certificate is being used as a CA - it MUST have CA=TRUE
                if is_ca_in_cert:
                    result.add_step("Basic Constraints", ValidationStatus.PASS,
                                    f"CA certificate with CA=TRUE (path_length={bc.value.path_length})")
                else:
                    result.add_step("Basic Constraints", ValidationStatus.FAIL,
                                    "Certificate used as CA but CA flag is FALSE")
            else:
                # This certificate is being used as an end-entity - it MUST have CA=FALSE
                if is_ca_in_cert:
                    result.add_step("Basic Constraints", ValidationStatus.FAIL,
                                    "End-entity certificate has CA=TRUE (should be FALSE)")
                else:
                    result.add_step("Basic Constraints", ValidationStatus.PASS,
                                    "End-entity certificate with CA=FALSE")
        except x509.extensions.ExtensionNotFound:
            if is_ca:
                result.add_step("Basic Constraints", ValidationStatus.FAIL,
                                "Missing Basic Constraints for CA certificate")
            else:
                result.add_step("Basic Constraints", ValidationStatus.PASS,
                                "No Basic Constraints (default CA=FALSE)")
    def _check_key_usage(self, cert: x509.Certificate, is_ca: bool, result: CertificateValidationResult):

        try:
            ku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)

            if is_ca:
                if ku.value.key_cert_sign:
                    result.add_step("Key Usage", ValidationStatus.PASS, "CA certificate has keyCertSign")
                else:
                    result.add_step("Key Usage", ValidationStatus.FAIL, "CA certificate missing keyCertSign")
            else:
                # For end-entity, check appropriate usage
                if ku.value.digital_signature or ku.value.key_encipherment:
                    result.add_step("Key Usage", ValidationStatus.PASS, "End-entity certificate has appropriate key usage")
                else:
                    result.add_step("Key Usage", ValidationStatus.PASS, "Key usage present")
        except x509.extensions.ExtensionNotFound:
            result.add_step("Key Usage", ValidationStatus.SKIP, "No Key Usage extension")

    def _check_extended_key_usage(self, cert: x509.Certificate, intended_usage: str, result: CertificateValidationResult):

        expected_oids = {
            'server': ExtendedKeyUsageOID.SERVER_AUTH,
            'client': ExtendedKeyUsageOID.CLIENT_AUTH,
            'code_signing': ExtendedKeyUsageOID.CODE_SIGNING,
        }

        expected_oid = expected_oids.get(intended_usage)
        if not expected_oid:
            result.add_step("Extended Key Usage", ValidationStatus.SKIP, f"No expected EKU for {intended_usage}")
            return

        try:
            eku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
            if expected_oid in eku.value:
                result.add_step("Extended Key Usage", ValidationStatus.PASS, f"Certificate has {intended_usage} EKU")
            else:
                result.add_step("Extended Key Usage", ValidationStatus.FAIL, f"Certificate missing {intended_usage} EKU")
        except x509.extensions.ExtensionNotFound:
            result.add_step("Extended Key Usage", ValidationStatus.FAIL, "No Extended Key Usage extension")