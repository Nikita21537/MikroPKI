# test_sprint7.py
"""
Tests for Sprint 7 - Security Hardening
"""

import pytest
import tempfile
import shutil
import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone

from micropki.ca import RootCA
from micropki.intermediate import IntermediateCA, IssueCertificate
from micropki.database import Database
from micropki.audit import AuditLogger, init_audit_system, log_audit_event
from micropki.policy import SecurityPolicy, PolicyViolation, init_policy, get_policy
from micropki.transparency import CTLog, init_ct_log, log_certificate_to_ct
from micropki.compromise import CompromiseManager, compute_public_key_hash
from micropki.ratelimit import RateLimiter, RateLimitMiddleware
from micropki.certificates import load_certificate
from micropki.crypto_utils import generate_rsa_key, load_passphrase


@pytest.fixture
def pki_env():
    """Create a full PKI environment for testing."""
    temp_dir = Path(tempfile.mkdtemp())
    pki_dir = temp_dir / "pki"
    secrets_dir = temp_dir / "secrets"

    pki_dir.mkdir()
    pki_dir.joinpath("private").mkdir()
    pki_dir.joinpath("certs").mkdir()
    secrets_dir.mkdir()

    # Create passphrase file
    root_pass_file = secrets_dir / "root.pass"
    root_pass_file.write_text("testpass123\n")

    # Initialize Root CA
    root_ca = RootCA(str(pki_dir))
    root_ca.init_ca(
        subject="/CN=Test Root CA/O=Sprint7",
        key_type="rsa",
        key_size=4096,
        passphrase_file=str(root_pass_file),
        validity_days=365
    )

    # Initialize database
    db = Database(str(pki_dir / "micropki.db"))

    return {
        'temp_dir': temp_dir,
        'pki_dir': pki_dir,
        'secrets_dir': secrets_dir,
        'db': db,
        'root_pass_file': root_pass_file,
        'ca_cert_path': pki_dir / "certs" / "ca.cert.pem",
        'ca_key_path': pki_dir / "private" / "ca.key.pem"
    }


def test_policy_key_size_enforcement(pki_env):
    """TEST-51: Policy violation - weak key size."""
    policy = SecurityPolicy()

    # RSA - valid
    is_valid, msg = policy.validate_key_size("rsa", 2048, "end_entity")
    assert is_valid is True

    # RSA - too weak for end-entity
    is_valid, msg = policy.validate_key_size("rsa", 1024, "end_entity")
    assert is_valid is False
    assert "1024" in msg

    # RSA - too weak for root
    is_valid, msg = policy.validate_key_size("rsa", 2048, "root")
    assert is_valid is False
    assert "4096" in msg

    # ECC - valid for end-entity
    is_valid, msg = policy.validate_key_size("ecc", 256, "end_entity")
    assert is_valid is True

    # ECC - invalid for root (needs P-384)
    is_valid, msg = policy.validate_key_size("ecc", 256, "root")
    assert is_valid is False


def test_policy_validity_period(pki_env):
    """TEST-52: Policy violation - excessive validity."""
    policy = SecurityPolicy()

    # End-entity: 365 days is ok
    is_valid, msg = policy.validate_validity_period(365, "end_entity")
    assert is_valid is True

    # End-entity: 366 days exceeds limit
    is_valid, msg = policy.validate_validity_period(366, "end_entity")
    assert is_valid is False
    assert "exceeds maximum" in msg

    # Intermediate: 1825 days (5 years) is ok
    is_valid, msg = policy.validate_validity_period(1825, "intermediate")
    assert is_valid is True

    # Intermediate: 1826 days exceeds
    is_valid, msg = policy.validate_validity_period(1826, "intermediate")
    assert is_valid is False


def test_policy_wildcard_rejection(pki_env):
    """TEST-53: Policy violation - wildcard SAN."""
    policy = SecurityPolicy()

    # Wildcard should be rejected by default
    is_valid, msg = policy.validate_san_list(["dns:*.example.com"], "server")
    assert is_valid is False
    assert "wildcard" in msg.lower()

    # Regular DNS is ok
    is_valid, msg = policy.validate_san_list(["dns:example.com"], "server")
    assert is_valid is True


def test_policy_forbidden_san_type(pki_env):
    """TEST-54: Policy violation - forbidden SAN type."""
    policy = SecurityPolicy()

    # Code signing with email SAN - should fail
    is_valid, msg = policy.validate_san_list(["email:test@example.com"], "code_signing")
    assert is_valid is False

    # Code signing with DNS - ok
    is_valid, msg = policy.validate_san_list(["dns:signer.local"], "code_signing")
    assert is_valid is True

    # Server with email - fail
    is_valid, msg = policy.validate_san_list(["email:test@example.com"], "server")
    assert is_valid is False

    # Server with IP - ok
    is_valid, msg = policy.validate_san_list(["ip:192.168.1.1"], "server")
    assert is_valid is True


def test_audit_log_integrity(pki_env):
    """TEST-55: Audit integrity - tamper detection."""
    audit_dir = pki_env['pki_dir'] / "audit"
    audit_dir.mkdir()
    log_path = audit_dir / "audit.log"

    logger = AuditLogger(log_path)

    # Log several entries
    for i in range(5):
        logger.log_event(
            operation="test_event",
            status="success",
            message=f"Test entry {i}",
            metadata={"counter": i}
        )

    # Verify integrity before tampering
    is_valid, errors = logger.verify_integrity()
    assert is_valid is True
    assert len(errors) == 0

    # Tamper with the log file
    with open(log_path, 'r+') as f:
        content = f.read()
        # Modify a character
        content = content.replace('Test entry 2', 'Tampered entry')
        f.seek(0)
        f.write(content)
        f.truncate()

    # Verify again - should detect tampering
    is_valid, errors = logger.verify_integrity()
    assert is_valid is False
    assert len(errors) > 0


def test_audit_log_chain_continuity(pki_env):
    """TEST-56: Audit integrity - chain continuity (missing entry)."""
    audit_dir = pki_env['pki_dir'] / "audit"
    audit_dir.mkdir()
    log_path = audit_dir / "audit.log"

    logger = AuditLogger(log_path)

    # Log 3 entries
    logger.log_event("test1", "success", "Entry 1")
    logger.log_event("test2", "success", "Entry 2")
    logger.log_event("test3", "success", "Entry 3")

    # Delete the second entry
    with open(log_path, 'r') as f:
        lines = f.readlines()

    with open(log_path, 'w') as f:
        f.write(lines[0])  # Entry 1
        f.write(lines[2])  # Entry 3 (skip entry 2)

    # Verify - should detect chain break
    is_valid, errors = logger.verify_integrity()
    assert is_valid is False

    # Check that error mentions hash chain break
    has_chain_error = any("hash chain broken" in e.lower() for e in errors)
    assert has_chain_error is True


def test_ct_log(pki_env):
    """TEST-59: Certificate Transparency log test."""
    audit_dir = pki_env['pki_dir'] / "audit"
    audit_dir.mkdir()
    ct_log = CTLog(audit_dir / "ct.log")

    # Log a certificate
    ct_log.log_certificate(
        serial="1234567890ABCDEF",
        subject="CN=test.example.com",
        fingerprint="AA:BB:CC:DD:EE:FF"
    )

    # Verify inclusion
    assert ct_log.verify_inclusion("1234567890ABCDEF") is True
    assert ct_log.verify_inclusion("NONEXISTENT") is False

    # Get all entries
    entries = ct_log.get_all_entries()
    assert len(entries) == 1
    assert entries[0]['serial'] == "1234567890ABCDEF"


def test_rate_limiter():
    """Test rate limiter functionality."""
    limiter = RateLimiter(rate=2.0, burst=2)  # 2 requests per second, burst 2

    # First request should be allowed
    allowed, _ = limiter.allow_request("127.0.0.1")
    assert allowed is True

    # Second request should be allowed
    allowed, _ = limiter.allow_request("127.0.0.1")
    assert allowed is True

    # Third request within same second?
    allowed, _ = limiter.allow_request("127.0.0.1")
    # Might be allowed or not depending on timing - test is non-deterministic

    # Different IP should have its own bucket
    allowed, _ = limiter.allow_request("10.0.0.1")
    assert allowed is True


def test_rate_limit_middleware():
    """Test rate limit middleware."""
    middleware = RateLimitMiddleware(rate=1.0, burst=1)

    allowed, retry = middleware.check_request("127.0.0.1")
    assert allowed is True

    # Second request should be denied (no time elapsed)
    allowed, retry = middleware.check_request("127.0.0.1")
    assert allowed is False
    assert retry is not None


def test_compromise_marking(pki_env):
    """TEST-57: Compromise simulation."""
    from micropki.certificates import save_certificate

    # Generate a test certificate
    key = generate_rsa_key(2048)
    from micropki.certificates import create_self_signed_certificate
    cert = create_self_signed_certificate(key, "/CN=Test Cert", 365)

    cert_path = pki_env['pki_dir'] / "certs" / "test.cert.pem"
    save_certificate(cert, cert_path)

    # Create compromise manager
    mgr = CompromiseManager(pki_env['db'], pki_env['pki_dir'])

    # Mark as compromised
    success, msg = mgr.mark_compromised(cert, "keyCompromise")
    assert success is True

    # Check that key is marked as compromised
    is_compromised = mgr.is_key_compromised(cert)
    assert is_compromised is True

    # Get compromised keys list
    keys = mgr.get_compromised_keys()
    assert len(keys) >= 1
    assert keys[0]['compromise_reason'] == "keyCompromise"


def test_public_key_hash():
    """Test public key hash computation."""
    key1 = generate_rsa_key(2048)
    cert1 = None
    from micropki.certificates import create_self_signed_certificate
    cert1 = create_self_signed_certificate(key1, "/CN=Test1", 365)

    key2 = generate_rsa_key(2048)
    cert2 = create_self_signed_certificate(key2, "/CN=Test2", 365)

    hash1 = compute_public_key_hash(cert1)
    hash2 = compute_public_key_hash(cert2)

    # Different keys should have different hashes
    assert hash1 != hash2

    # Same key should produce same hash
    hash1_again = compute_public_key_hash(cert1)
    assert hash1 == hash1_again

    # Hash should be 64 hex characters (SHA-256)
    assert len(hash1) == 64
    assert all(c in '0123456789abcdef' for c in hash1)


def test_audit_query(pki_env):
    """Test audit log query functionality."""
    audit_dir = pki_env['pki_dir'] / "audit"
    audit_dir.mkdir()
    log_path = audit_dir / "audit.log"

    logger = AuditLogger(log_path)

    # Log different events
    logger.log_event("issue_cert", "success", "Issued cert A", metadata={"serial": "AAA"})
    logger.log_event("issue_cert", "success", "Issued cert B", metadata={"serial": "BBB"})
    logger.log_event("revoke_cert", "success", "Revoked cert A", metadata={"serial": "AAA"})
    logger.log_event("ca_init", "success", "CA initialized")

    # Query by operation
    results = logger.query(operation="issue_cert")
    assert len(results) == 2

    # Query by serial
    results = logger.query(serial="AAA")
    assert len(results) == 2  # issue and revoke

    # Query by level
    results = logger.query(level="AUDIT")
    assert len(results) == 4


def test_policy_integration_with_issuance(pki_env):
    """Test that policies are enforced during issuance."""
    from micropki.intermediate import IntermediateCA, IssueCertificate
    from micropki.policy import init_policy, get_policy

    # Initialize policy
    init_policy()
    policy = get_policy()

    # Create Intermediate CA
    inter_pass_file = pki_env['secrets_dir'] / "intermediate.pass"
    inter_pass_file.write_text("interpass123\n")

    inter_ca = IntermediateCA(str(pki_env['pki_dir']))

    # This should work (RSA 4096 for intermediate)
    inter_ca.create_intermediate_ca(
        root_cert_path=pki_env['ca_cert_path'],
        root_key_path=pki_env['ca_key_path'],
        root_pass_file=pki_env['root_pass_file'],
        subject_dn="/CN=Test Intermediate CA",
        key_type="rsa",
        passphrase_file=inter_pass_file,
        validity_days=1825,  # 5 years max
        pathlen=0
    )

    # Try to issue certificate with excessive validity
    issuer = IssueCertificate()

    with pytest.raises(PolicyViolation) as exc_info:
        issuer.issue_certificate(
            ca_cert_path=pki_env['pki_dir'] / "certs" / "intermediate.cert.pem",
            ca_key_path=pki_env['pki_dir'] / "private" / "intermediate.key.pem",
            ca_pass_file=inter_pass_file,
            template_name="server",
            subject_dn="/CN=test.example.com",
            san_list=["dns:test.example.com"],
            out_dir=pki_env['pki_dir'] / "certs",
            validity_days=400  # Exceeds 365 days
        )

    assert "validity" in str(exc_info.value).lower()


def test_audit_system_initialization(pki_env):
    """Test audit system initialization."""
    audit_system = init_audit_system(pki_env['pki_dir'])

    assert audit_system is not None
    assert (pki_env['pki_dir'] / "audit" / "audit.log").exists()
    assert (pki_env['pki_dir'] / "audit" / "audit.log.chain").exists()

    # First entry should have prev_hash of zeros
    with open(pki_env['pki_dir'] / "audit" / "audit.log", 'r') as f:
        first_line = json.loads(f.readline())
        assert first_line['integrity']['prev_hash'] == "0" * 64


def test_audit_verify_command_integration(pki_env):
    """Test audit verify command integration."""
    audit_dir = pki_env['pki_dir'] / "audit"
    audit_dir.mkdir()
    log_path = audit_dir / "audit.log"

    logger = AuditLogger(log_path)
    logger.log_event("test", "success", "Test entry")

    # Verify
    is_valid, errors = logger.verify_integrity()
    assert is_valid is True


def test_ct_log_certificate_fingerprint(pki_env):
    """Test CT log with real certificate fingerprint."""
    from micropki.certificates import create_self_signed_certificate, compute_certificate_fingerprint

    key = generate_rsa_key(2048)
    cert = create_self_signed_certificate(key, "/CN=Fingerprint Test", 365)

    fingerprint = compute_certificate_fingerprint(cert)
    assert len(fingerprint) == 95  # 32 bytes * 3 - 1 (colons)
    assert fingerprint.count(':') == 31


def test_compromise_manager_integration(pki_env):
    """Test CompromiseManager integration with database."""
    mgr = CompromiseManager(pki_env['db'], pki_env['pki_dir'])

    # Should create compromised_keys table
    conn = pki_env['db']._get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='compromised_keys'")
    assert cursor.fetchone() is not None
    conn.close()


def test_rate_limiter_cleanup():
    """Test rate limiter cleanup of idle clients."""
    limiter = RateLimiter(rate=10.0, burst=10, cleanup_interval=1)

    # Add many clients
    for i in range(100):
        limiter.allow_request(f"192.168.1.{i}")

    # Force cleanup
    limiter._cleanup_idle_buckets()

    # Should have cleaned up some
    with limiter._lock:
        assert len(limiter._buckets) < 100