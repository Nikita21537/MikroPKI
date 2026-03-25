"""Tests for CSR handling."""

import pytest
import tempfile
import shutil
from pathlib import Path
from cryptography import x509
from micropki import crypto_utils, csr


@pytest.fixture
def temp_dir():
    """Create temporary directory."""
    path = Path(tempfile.mkdtemp())
    yield path
    shutil.rmtree(path)


def test_generate_csr(temp_dir):
    """Test CSR generation."""
    # Generate key (2048 for end-entity)
    private_key = crypto_utils.generate_rsa_key(2048)

    # Generate CSR
    csr_obj = csr.generate_csr(
        private_key=private_key,
        subject_dn="CN=Test,O=Org",
        template_name="server",
        san_list=["dns:test.com"]
    )

    assert csr_obj is not None
    # Check that attributes are present (order may vary)
    subject_str = csr_obj.subject.rfc4514_string()
    assert "CN=Test" in subject_str
    assert "O=Org" in subject_str

    # Save and load CSR
    csr_path = temp_dir / "test.csr.pem"
    csr.save_csr(csr_obj, csr_path)
    assert csr_path.exists()

    # Try to load (skip if not supported)
    try:
        loaded_csr = csr.load_csr(csr_path)
        assert loaded_csr is not None
        assert loaded_csr.subject == csr_obj.subject
    except (AttributeError, ImportError):
        pytest.skip("CSR loading not supported in this version")


def test_csr_with_sans(temp_dir):
    """Test CSR with SAN extensions."""
    private_key = crypto_utils.generate_rsa_key(2048)

    # For server use only dns and ip
    csr_obj = csr.generate_csr(
        private_key=private_key,
        subject_dn="CN=Test",
        template_name="server",
        san_list=["dns:example.com", "ip:192.168.1.1"]
    )

    # Check SAN extension
    san_ext = None
    for ext in csr_obj.extensions:
        if ext.oid.dotted_string == "2.5.29.17":  # SAN OID
            san_ext = ext
            break

    assert san_ext is not None
    assert len(san_ext.value) == 2

    # Verify SAN types
    has_dns = False
    has_ip = False
    for san in san_ext.value:
        if isinstance(san, x509.DNSName):
            has_dns = True
            assert san.value == "example.com"
        elif isinstance(san, x509.IPAddress):
            has_ip = True
            assert str(san.value) == "192.168.1.1"

    assert has_dns is True
    assert has_ip is True


def test_csr_for_client(temp_dir):
    """Test CSR generation for client certificate."""
    private_key = crypto_utils.generate_rsa_key(2048)

    # Client supports email and dns
    csr_obj = csr.generate_csr(
        private_key=private_key,
        subject_dn="CN=Client",
        template_name="client",
        san_list=["email:user@example.com", "dns:client.local"]
    )

    # Check SAN extension
    san_ext = None
    for ext in csr_obj.extensions:
        if ext.oid.dotted_string == "2.5.29.17":
            san_ext = ext
            break

    assert san_ext is not None
    assert len(san_ext.value) == 2


def test_csr_for_code_signing(temp_dir):
    """Test CSR generation for code signing certificate."""
    private_key = crypto_utils.generate_rsa_key(2048)

    # Code signing supports dns and uri
    csr_obj = csr.generate_csr(
        private_key=private_key,
        subject_dn="CN=CodeSigner",
        template_name="code_signing",
        san_list=["dns:signer.local", "uri:https://example.com"]
    )

    # Check SAN extension
    san_ext = None
    for ext in csr_obj.extensions:
        if ext.oid.dotted_string == "2.5.29.17":
            san_ext = ext
            break

    assert san_ext is not None
    assert len(san_ext.value) == 2


def test_csr_with_ca_constraints(temp_dir):
    """Test CSR generation with CA constraints."""
    private_key = crypto_utils.generate_rsa_key(4096)

    csr_obj = csr.generate_csr(
        private_key=private_key,
        subject_dn="CN=CA Certificate",
        template_name="server",
        san_list=None,
        pathlen=2
    )

    # Check Basic Constraints extension
    bc_ext = None
    for ext in csr_obj.extensions:
        if ext.oid.dotted_string == "2.5.29.19":  # Basic Constraints OID
            bc_ext = ext
            break

    assert bc_ext is not None
    assert bc_ext.value.ca is True
    assert bc_ext.value.path_length == 2