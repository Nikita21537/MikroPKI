import re
from datetime import datetime, timedelta
from typing import Optional, List, Tuple
from pathlib import Path
import yaml


from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from . import templates
from .certificates import parse_dn_string, load_certificate


class PolicyViolation(Exception):

    pass


class SecurityPolicy:

    # RSA key size limits (min, max)
    RSA_MIN_END_ENTITY = 2048
    RSA_MIN_INTERMEDIATE = 3072
    RSA_MIN_ROOT = 4096

    # ECC key size requirements
    ECC_END_ENTITY_ALLOWED = [256, 384]
    ECC_CA_ALLOWED = [384]  # P-384 only for CAs

    # Validity limits (days)
    MAX_VALIDITY_ROOT = 3650  # 10 years
    MAX_VALIDITY_INTERMEDIATE = 1825  # 5 years
    MAX_VALIDITY_END_ENTITY = 365  # 1 year

    # Wildcard policy
    ALLOW_WILDCARDS = False  # Default: reject wildcards

    def __init__(self, config_path: Optional[Path] = None):

        self.config_path = config_path
        if config_path and config_path.exists():
            self._load_config(config_path)

    def _load_config(self, config_path: Path) -> None:

        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            # Override settings if present
            if 'policy' in config:
                pol = config['policy']
                self.ALLOW_WILDCARDS = pol.get('allow_wildcards', self.ALLOW_WILDCARDS)
                # Other configurable options can be added here

        except Exception as e:
            # Log but continue with defaults
            pass

    def validate_key_size(
            self,
            key_type: str,
            key_size: int,
            cert_type: str  # "root", "intermediate", "end_entity"
    ) -> Tuple[bool, str]:

        if key_type == "rsa":
            if cert_type == "root":
                if key_size < self.RSA_MIN_ROOT:
                    return False, f"Root CA RSA key size must be at least {self.RSA_MIN_ROOT} bits"
            elif cert_type == "intermediate":
                if key_size < self.RSA_MIN_INTERMEDIATE:
                    return False, f"Intermediate CA RSA key size must be at least {self.RSA_MIN_INTERMEDIATE} bits"
            else:  # end_entity
                if key_size < self.RSA_MIN_END_ENTITY:
                    return False, f"End-entity RSA key size must be at least {self.RSA_MIN_END_ENTITY} bits"

            # Check for unreasonably large keys (performance)
            if key_size > 16384:
                return False, f"RSA key size {key_size} exceeds maximum (16384)"

        elif key_type == "ecc":
            allowed = self.ECC_CA_ALLOWED if cert_type != "end_entity" else self.ECC_END_ENTITY_ALLOWED
            if key_size not in allowed:
                return False, f"ECC key size {key_size} not allowed for {cert_type}. Allowed: {allowed}"
        else:
            return False, f"Unknown key type: {key_type}"

        return True, ""

    def validate_validity_period(
            self,
            validity_days: int,
            cert_type: str  # "root", "intermediate", "end_entity"
    ) -> Tuple[bool, str]:

        if cert_type == "root":
            max_days = self.MAX_VALIDITY_ROOT
        elif cert_type == "intermediate":
            max_days = self.MAX_VALIDITY_INTERMEDIATE
        else:
            max_days = self.MAX_VALIDITY_END_ENTITY

        if validity_days > max_days:
            return False, f"Validity period {validity_days} days exceeds maximum {max_days} days for {cert_type}"

        if validity_days <= 0:
            return False, f"Validity period must be positive"

        return True, ""

    def validate_san_list(
            self,
            san_list: List[str],
            template_name: str
    ) -> Tuple[bool, str]:

        if not san_list:
            # Server certificates require at least one SAN
            if template_name == "server":
                return False, "Server certificate requires at least one SAN"
            return True, ""


        allowed_types = {
            "server": ["dns", "ip"],
            "client": ["dns", "email"],
            "code_signing": ["dns", "uri"]
        }.get(template_name, ["dns"])

        for san in san_list:
            if ':' not in san:
                return False, f"Invalid SAN format: {san}"

            san_type, san_value = san.split(':', 1)


            if san_type not in allowed_types:
                return False, f"SAN type '{san_type}' not allowed for {template_name}. Allowed: {allowed_types}"


            if san_type == "dns" and '*' in san_value and not self.ALLOW_WILDCARDS:
                return False, f"Wildcard DNS name '{san_value}' is not allowed by policy"

        return True, ""

    def validate_signature_algorithm(
            self,
            csr: Optional[x509.CertificateSigningRequest] = None,
            key_type: Optional[str] = None,
            private_key=None
    ) -> Tuple[bool, str]:

        if csr:

            algo = csr.signature_hash_algorithm
            if algo is None:
                return False, "CSR has no signature algorithm"

            algo_name = algo.name.upper()

            if algo_name in ['SHA1', 'MD5']:
                return False, f"CSR uses weak hash algorithm: {algo_name}"

        if key_type == "rsa":

            pass
        elif key_type == "ecc":

            pass

        return True, ""

    def validate_path_length(
            self,
            pathlen: int,
            is_intermediate: bool = False
    ) -> Tuple[bool, str]:

        if is_intermediate and pathlen != 0:
            return False, f"Intermediate CA must have path length 0 (got {pathlen})"

        if pathlen < 0:
            return False, f"Path length cannot be negative"

        return True, ""

    def validate_csr_extensions(
            self,
            csr: x509.CertificateSigningRequest,
            template_name: str
    ) -> Tuple[bool, str]:

        # Check for Basic Constraints
        for ext in csr.extensions:
            if ext.oid.dotted_string == "2.5.29.19":  # Basic Constraints
                if ext.value.ca and template_name != "intermediate":
                    return False, "CSR requests CA certificate but template is for end-entity"

        return True, ""

    def check_certificate_policy(
            self,
            certificate: x509.Certificate,
            cert_type: str
    ) -> Tuple[bool, List[str]]:

        violations = []


        pub_key = certificate.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_size = pub_key.key_size
            is_valid, msg = self.validate_key_size("rsa", key_size, cert_type)
            if not is_valid:
                violations.append(msg)
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_size = pub_key.curve.key_size
            is_valid, msg = self.validate_key_size("ecc", key_size, cert_type)
            if not is_valid:
                violations.append(msg)


        now = datetime.now()
        not_after = certificate.not_valid_after
        if hasattr(not_after, 'tzinfo') and not_after.tzinfo is not None:
            not_after = not_after.replace(tzinfo=None)

        remaining_days = (not_after - now).days
        if remaining_days < 0:
            violations.append("Certificate is expired")

        return len(violations) == 0, violations



_policy: Optional[SecurityPolicy] = None


def get_policy() -> SecurityPolicy:

    global _policy
    if _policy is None:
        _policy = SecurityPolicy()
    return _policy


def init_policy(config_path: Optional[Path] = None) -> SecurityPolicy:

    global _policy
    _policy = SecurityPolicy(config_path)
    return _policy