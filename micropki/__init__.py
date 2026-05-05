__version__ = "0.7.0"

# Core modules
from .ca import RootCA
from .intermediate import IntermediateCA, IssueCertificate
from .database import Database
from .serial import SerialGenerator
from .certificates import load_certificate, save_certificate, compute_certificate_fingerprint
from .crypto_utils import generate_rsa_key, generate_ecc_key

# Revocation modules
from .revocation import RevocationManager, CRLManager, RevocationReason

# OCSP modules
from .ocsp import create_ocsp_signing_certificate
from .ocsp_responder import OCSPResponderServer

# Sprint 7: Audit modules
from .audit import (
    AuditLogger,
    init_audit_system,
    get_audit_logger,
    log_audit_event,
    AuditEntry
)

# Sprint 7: Policy modules
from .policy import (
    SecurityPolicy,
    init_policy,
    get_policy,
    PolicyViolation
)


# Sprint 7: Rate limiting
from .ratelimit import (
    RateLimiter,
    RateLimitMiddleware,
    init_rate_limiter,
    get_rate_limiter,
    TokenBucket
)

# Sprint 7: Certificate Transparency
from .transparency import (
    CTLog,
    init_ct_log,
    get_ct_log,
    log_certificate_to_ct
)

# Sprint 7: Compromise detection
from .compromise import (
    CompromiseManager,
    CompromiseChecker,
    compute_public_key_hash
)


# Lazy imports for optional modules
def get_validation_module():
    from .validation import (
        PathValidator,
        ChainBuilder,
        ChainValidationResult,
        CertificateValidationResult,
        ValidationStatus
    )
    return (
        PathValidator,
        ChainBuilder,
        ChainValidationResult,
        CertificateValidationResult,
        ValidationStatus
    )


def get_revocation_check_module():
    from .revocation_check import (
        RevocationChecker,
        RevocationStatus,
        CRLChecker,
        OCSPChecker
    )
    return RevocationChecker, RevocationStatus, CRLChecker, OCSPChecker


def get_client_cli():
    from .client_cli import ClientCLI
    return ClientCLI


__all__ = [
    # Core
    'RootCA',
    'IntermediateCA',
    'IssueCertificate',
    'Database',
    'SerialGenerator',
    'load_certificate',
    'save_certificate',
    'compute_certificate_fingerprint',
    'generate_rsa_key',
    'generate_ecc_key',

    # Revocation
    'RevocationManager',
    'CRLManager',
    'RevocationReason',

    # OCSP
    'create_ocsp_signing_certificate',
    'OCSPResponderServer',

    # Audit (Sprint 7)
    'AuditLogger',
    'init_audit_system',
    'get_audit_logger',
    'log_audit_event',
    'AuditEntry',

    # Policy (Sprint 7)
    'SecurityPolicy',
    'init_policy',
    'get_policy',
    'PolicyViolation',

    # Rate Limiting (Sprint 7)
    'RateLimiter',
    'RateLimitMiddleware',
    'init_rate_limiter',
    'get_rate_limiter',
    'TokenBucket',

    # Certificate Transparency (Sprint 7)
    'CTLog',
    'init_ct_log',
    'get_ct_log',
    'log_certificate_to_ct',

    # Compromise (Sprint 7)
    'CompromiseManager',
    'CompromiseChecker',
    'compute_public_key_hash',

    # Lazy modules
    'get_validation_module',
    'get_revocation_check_module',
    'get_client_cli',
]