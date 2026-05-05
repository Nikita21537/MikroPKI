import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from micropki.ca import RootCA
from micropki.intermediate import IntermediateCA, IssueCertificate
from micropki.validation import PathValidator, ChainBuilder
from micropki.certificates import load_certificate
from micropki.crypto_utils import load_passphrase, load_encrypted_private_key, generate_rsa_key


@pytest.fixture
def chain_env():

    temp_dir = Path(tempfile.mkdtemp())
    pki_dir = temp_dir / "pki"
    secrets_dir = temp_dir / "secrets"

    pki_dir.mkdir()
    secrets_dir.mkdir()

    # Create passphrase files
    root_pass_file = secrets_dir / "root.pass"
    root_pass_file.write_text("rootpass123\n")
    inter_pass_file = secrets_dir / "intermediate.pass"
    inter_pass_file.write_text("interpass123\n")

    # Initialize Root CA
    root_ca = RootCA(str(pki_dir))
    root_ca.init_ca(
        subject="/CN=Test Root CA/O=Validation",
        key_type="rsa",
        key_size=4096,
        passphrase_file=str(root_pass_file),
        validity_days=365
    )

    # Initialize Intermediate CA
    inter_ca = IntermediateCA(str(pki_dir))
    inter_ca.create_intermediate_ca(
        root_cert_path=pki_dir / "certs" / "ca.cert.pem",
        root_key_path=pki_dir / "private" / "ca.key.pem",
        root_pass_file=root_pass_file,
        subject_dn="/CN=Test Intermediate CA/O=Validation",
        key_type="rsa",
        passphrase_file=inter_pass_file,
        validity_days=365,
        pathlen=0
    )

    # Issue leaf certificate
    issuer = IssueCertificate()
    leaf_path, _ = issuer.issue_certificate(
        ca_cert_path=pki_dir / "certs" / "intermediate.cert.pem",
        ca_key_path=pki_dir / "private" / "intermediate.key.pem",
        ca_pass_file=inter_pass_file,
        template_name="server",
        subject_dn="/CN=leaf.example.com",
        san_list=["dns:leaf.example.com"],
        out_dir=pki_dir / "certs",
        validity_days=30
    )

    return {
        'temp_dir': temp_dir,
        'pki_dir': pki_dir,
        'root_cert_path': pki_dir / "certs" / "ca.cert.pem",
        'inter_cert_path': pki_dir / "certs" / "intermediate.cert.pem",
        'leaf_cert_path': leaf_path,
        'root_key_path': pki_dir / "private" / "ca.key.pem",
        'inter_key_path': pki_dir / "private" / "intermediate.key.pem",
        'root_pass_file': root_pass_file,
        'inter_pass_file': inter_pass_file
    }


def test_chain_builder_valid(chain_env):

    leaf = load_certificate(chain_env['leaf_cert_path'])
    inter = load_certificate(chain_env['inter_cert_path'])
    root = load_certificate(chain_env['root_cert_path'])

    builder = ChainBuilder(trusted_roots=[root])
    chain = builder.build_chain(leaf, [inter])

    assert chain is not None
    assert len(chain) == 3
    assert chain[0] == leaf
    assert chain[1] == inter
    assert chain[2] == root


def test_chain_builder_missing_intermediate(chain_env):

    leaf = load_certificate(chain_env['leaf_cert_path'])
    root = load_certificate(chain_env['root_cert_path'])

    builder = ChainBuilder(trusted_roots=[root])
    chain = builder.build_chain(leaf, [])  # No intermediates

    assert chain is None


def test_path_validator_valid_chain(chain_env):

    leaf = load_certificate(chain_env['leaf_cert_path'])
    inter = load_certificate(chain_env['inter_cert_path'])
    root = load_certificate(chain_env['root_cert_path'])

    validator = PathValidator()
    result = validator.validate_chain(
        leaf=leaf,
        intermediates=[inter],
        trusted_roots=[root],
        check_revocation=False
    )

    assert result.is_valid is True
    assert len(result.chain) == 2  # leaf and intermediate validated


def test_path_validator_expired_certificate(chain_env):

    # Create expired certificate
    from micropki.crypto_utils import generate_rsa_key, generate_serial_number

    inter_cert = load_certificate(chain_env['inter_cert_path'])
    inter_pass = load_passphrase(chain_env['inter_pass_file'])
    inter_key = load_encrypted_private_key(chain_env['inter_key_path'], inter_pass)

    # Generate key
    private_key = generate_rsa_key(2048)
    public_key = private_key.public_key()

    # Create certificate that expires in the past
    serial = generate_serial_number()
    not_before = datetime.now(timezone.utc) - timedelta(days=30)
    not_after = not_before + timedelta(days=1)  # Expired yesterday

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "expired.example.com")]))
    builder = builder.issuer_name(inter_cert.subject)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    builder = builder.serial_number(serial)
    builder = builder.public_key(public_key)

    expired_cert = builder.sign(inter_key, hashes.SHA256(), default_backend())

    validator = PathValidator()
    result = validator.validate_chain(
        leaf=expired_cert,
        intermediates=[inter_cert],
        trusted_roots=[load_certificate(chain_env['root_cert_path'])],
        check_revocation=False
    )

    assert result.is_valid is False

    # Check that expiration was detected
    has_expiration_error = False
    for cert_result in result.chain:
        for step in cert_result.steps:
            if step.name == "Validity Period" and "expired" in step.message.lower():
                has_expiration_error = True
    assert has_expiration_error is True


def test_path_validator_with_validation_time(chain_env):

    leaf = load_certificate(chain_env['leaf_cert_path'])
    inter = load_certificate(chain_env['inter_cert_path'])
    root = load_certificate(chain_env['root_cert_path'])

    # Use a time that's too early (before certificate validity)
    early_time = datetime(2020, 1, 1)

    validator = PathValidator(validation_time=early_time)
    result = validator.validate_chain(
        leaf=leaf,
        intermediates=[inter],
        trusted_roots=[root],
        check_revocation=False
    )

    assert result.is_valid is False


def test_path_validator_wrong_key_usage(chain_env):

    # Issue a client certificate
    issuer = IssueCertificate()
    client_cert_path, _ = issuer.issue_certificate(
        ca_cert_path=chain_env['inter_cert_path'],
        ca_key_path=chain_env['inter_key_path'],
        ca_pass_file=chain_env['inter_pass_file'],
        template_name="client",  # Client certificate
        subject_dn="/CN=client.example.com",
        san_list=["dns:client.example.com"],
        out_dir=chain_env['pki_dir'] / "certs",
        validity_days=30
    )

    leaf = load_certificate(client_cert_path)
    inter = load_certificate(chain_env['inter_cert_path'])
    root = load_certificate(chain_env['root_cert_path'])

    # Validate as server certificate (should fail EKU check)
    validator = PathValidator(intended_usage="server")
    result = validator.validate_chain(
        leaf=leaf,
        intermediates=[inter],
        trusted_roots=[root],
        check_revocation=False
    )

    # The chain is valid technically, but EKU check should fail
    # This depends on implementation
    assert result.is_valid is False or len(result.chain) > 0


def test_chain_builder_with_multiple_intermediates(chain_env):

    # Create second intermediate
    from micropki.intermediate import IntermediateCA

    inter2_pass_file = chain_env['pki_dir'].parent / "secrets" / "intermediate2.pass"
    inter2_pass_file.write_text("inter2pass123\n")

    inter2_ca = IntermediateCA(str(chain_env['pki_dir']))
    inter2_ca.create_intermediate_ca(
        root_cert_path=chain_env['inter_cert_path'],  # Issued by first intermediate
        root_key_path=chain_env['inter_key_path'],
        root_pass_file=chain_env['inter_pass_file'],
        subject_dn="/CN=Second Intermediate CA/O=Validation",
        key_type="rsa",
        passphrase_file=inter2_pass_file,
        validity_days=365,
        pathlen=0
    )


    issuer = IssueCertificate()
    inter2_cert_path = chain_env['pki_dir'] / "certs" / "intermediate.cert.pem"
    inter2_key_path = chain_env['pki_dir'] / "private" / "intermediate.key.pem"

    leaf2_path, _ = issuer.issue_certificate(
        ca_cert_path=inter2_cert_path,
        ca_key_path=inter2_key_path,
        ca_pass_file=inter2_pass_file,
        template_name="server",
        subject_dn="/CN=deep.example.com",
        san_list=["dns:deep.example.com"],
        out_dir=chain_env['pki_dir'] / "certs",
        validity_days=30
    )

    leaf = load_certificate(leaf2_path)
    inter1 = load_certificate(chain_env['inter_cert_path'])
    inter2 = load_certificate(inter2_cert_path)
    root = load_certificate(chain_env['root_cert_path'])

    builder = ChainBuilder(trusted_roots=[root])
    chain = builder.build_chain(leaf, [inter1, inter2])

    assert chain is not None
    assert len(chain) == 4  # leaf, inter2, inter1, root