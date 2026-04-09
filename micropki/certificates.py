from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Union, Optional



from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend


def parse_dn_string(dn_string: str) -> x509.Name:

    attributes = []


    dn_string = dn_string.strip()


    if dn_string.startswith('/'):

        parts = dn_string[1:].split('/')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                attributes.append(_create_name_attribute(key.strip(), value.strip()))
    else:

        parts = dn_string.split(',')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                attributes.append(_create_name_attribute(key.strip(), value.strip()))

    if not attributes:
        raise ValueError(f"Could not parse DN string: {dn_string}")

    return x509.Name(attributes)


def _create_name_attribute(key: str, value: str) -> x509.NameAttribute:

    key = key.upper()

    oid_map = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'E': NameOID.EMAIL_ADDRESS,
        'EMAIL': NameOID.EMAIL_ADDRESS,
        'EMAILADDRESS': NameOID.EMAIL_ADDRESS,
    }

    if key not in oid_map:
        raise ValueError(f"Unknown DN component: {key}")

    return x509.NameAttribute(oid_map[key], value)


def create_self_signed_certificate(
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        subject_dn: str,
        validity_days: int,
        serial_number: Optional[int] = None
) -> x509.Certificate:


    subject = parse_dn_string(subject_dn)

    issuer = subject

    if serial_number is None:
        from .crypto_utils import generate_serial_number
        serial_number = generate_serial_number()

    if serial_number <= 0:
        raise ValueError("Serial number must be positive")
    if serial_number.bit_length() >= 160:
        raise ValueError("Serial number must be less than 2^159 (max 159 bits)")

    not_valid_before = datetime.now(timezone.utc).replace(tzinfo=None)
    not_valid_after = not_valid_before + timedelta(days=validity_days)

    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(ski, critical=False)

    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)
    builder = builder.add_extension(aki, critical=False)

    if isinstance(private_key, rsa.RSAPrivateKey):
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
    else:
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA384(),
            backend=default_backend()
        )

    return certificate


def save_certificate(certificate: x509.Certificate, cert_path: Path) -> None:

    cert_path.parent.mkdir(parents=True, exist_ok=True)

    with open(cert_path, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))


def verify_certificate(cert_path: Path) -> bool:

    with open(cert_path, 'rb') as f:
        cert_data = f.read()

    certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

    if certificate.issuer != certificate.subject:
        return False

    public_key = certificate.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        else:
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm)
            )
        return True
    except Exception:
        return False


def load_certificate(cert_path: Path) -> x509.Certificate:

    with open(cert_path, 'rb') as f:
        cert_data = f.read()

    return x509.load_pem_x509_certificate(cert_data, default_backend())