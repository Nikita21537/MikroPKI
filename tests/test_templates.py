"""Tests for certificate templates."""

import pytest
from micropki import templates


def test_server_template():
    """Test server template."""
    template = templates.get_template("server")

    # Check key usage
    ku = template.get_key_usage()
    assert ku.digital_signature is True
    assert ku.key_encipherment is True
    assert ku.key_cert_sign is False

    # Check EKU
    eku = template.get_extended_key_usage()
    assert len(eku) == 1
    assert eku[0].dotted_string == "1.3.6.1.5.5.7.3.1"  # serverAuth

    # Check SAN validation
    template.validate_sans(["dns:example.com", "ip:192.168.1.1"])

    with pytest.raises(ValueError):
        template.validate_sans([])

    with pytest.raises(ValueError, match="does not support email SAN type"):
        template.validate_sans(["email:test@example.com"])


def test_client_template():
    """Test client template."""
    template = templates.get_template("client")

    ku = template.get_key_usage()
    assert ku.digital_signature is True
    assert ku.key_agreement is True

    eku = template.get_extended_key_usage()
    assert eku[0].dotted_string == "1.3.6.1.5.5.7.3.2"  # clientAuth

    # SAN validation
    template.validate_sans(["dns:client.local", "email:user@example.com"])

    with pytest.raises(ValueError, match="supports only DNS and email"):
        template.validate_sans(["ip:192.168.1.1"])


def test_code_signing_template():
    """Test code signing template."""
    template = templates.get_template("code_signing")

    ku = template.get_key_usage()
    assert ku.digital_signature is True
    assert ku.key_encipherment is False

    eku = template.get_extended_key_usage()
    assert eku[0].dotted_string == "1.3.6.1.5.5.7.3.3"  # codeSigning

    # SAN validation
    template.validate_sans(["dns:signer.local", "uri:https://example.com"])

    with pytest.raises(ValueError, match="supports only DNS and URI"):
        template.validate_sans(["ip:192.168.1.1"])

    with pytest.raises(ValueError, match="supports only DNS and URI"):
        template.validate_sans(["email:test@example.com"])


def test_build_san_extension():
    """Test SAN extension building."""
    # Valid SANs for server (only dns and ip)
    san_ext = templates.build_san_extension(
        ["dns:example.com", "ip:192.168.1.1"],
        "server"
    )
    assert len(san_ext) == 2

    # Test for client (supports email and dns)
    san_ext_client = templates.build_san_extension(
        ["email:test@example.com", "dns:client.local"],
        "client"
    )
    assert len(san_ext_client) == 2

    # Test for code_signing (supports dns and uri)
    san_ext_code = templates.build_san_extension(
        ["dns:signer.local", "uri:https://example.com"],
        "code_signing"
    )
    assert len(san_ext_code) == 2

    # Negative test: server with email should raise error
    with pytest.raises(ValueError, match="does not support email SAN type"):
        templates.build_san_extension(
            ["email:test@example.com"],
            "server"
        )

    # Negative test: client with ip should raise error
    with pytest.raises(ValueError, match="supports only DNS and email"):
        templates.build_san_extension(
            ["ip:192.168.1.1"],
            "client"
        )

    # Negative test: invalid SAN format
    with pytest.raises(ValueError, match="Invalid SAN format"):
        templates.build_san_extension(["invalid"], "server")

    # Negative test: invalid IP
    with pytest.raises(ValueError, match="Invalid IP address"):
        templates.build_san_extension(["ip:invalid"], "server")


def test_template_validation_for_all_types():
    """Test that templates reject invalid SAN types."""
    # Server rejects email
    server_template = templates.get_template("server")
    with pytest.raises(ValueError):
        server_template.validate_sans(["email:test@example.com"])

    # Client rejects IP
    client_template = templates.get_template("client")
    with pytest.raises(ValueError):
        client_template.validate_sans(["ip:192.168.1.1"])

    # Code signing rejects email and IP
    code_template = templates.get_template("code_signing")
    with pytest.raises(ValueError):
        code_template.validate_sans(["email:test@example.com"])
    with pytest.raises(ValueError):
        code_template.validate_sans(["ip:192.168.1.1"])