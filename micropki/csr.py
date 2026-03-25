"""Certificate Signing Request (CSR) handling."""

from pathlib import Path
from typing import Optional, Union, List

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

from . import crypto_utils, templates


def generate_csr(
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    subject_dn: str,
    template_name: str,
    san_list: Optional[List[str]] = None,
    pathlen: Optional[int] = None
) -> x509.CertificateSigningRequest:
    """
    Generate a PKCS#10 Certificate Signing Request.

    Args:
        private_key: Private key for the CSR
        subject_dn: Distinguished Name
        template_name: Certificate template (server, client, code_signing)
        san_list: List of SAN entries
        pathlen: Path length constraint for CA certificates

    Returns:
        CertificateSigningRequest object
    """
    from .certificates import parse_dn_string

    # Parse subject
    subject = parse_dn_string(subject_dn)

    # Create CSR builder
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)

    # Add SAN extension if provided
    if san_list:
        san_ext = templates.build_san_extension(san_list, template_name)
        builder = builder.add_extension(san_ext, critical=False)

    # Add Basic Constraints if this is a CA CSR
    if pathlen is not None:
        # CA certificate CSR - include Basic Constraints
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=pathlen),
            critical=True
        )

    # Sign the CSR
    if isinstance(private_key, rsa.RSAPrivateKey):
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    else:
        csr = builder.sign(private_key, hashes.SHA384(), default_backend())

    return csr


def save_csr(csr: x509.CertificateSigningRequest, csr_path: Path) -> None:
    """
    Save CSR to PEM file.

    Args:
        csr: CertificateSigningRequest object
        csr_path: Path where to save the CSR
    """
    csr_path.parent.mkdir(parents=True, exist_ok=True)

    with open(csr_path, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def load_csr(csr_path: Path) -> x509.CertificateSigningRequest:
    """
    Load CSR from PEM file.

    Args:
        csr_path: Path to CSR file

    Returns:
        CertificateSigningRequest object
    """
    with open(csr_path, 'rb') as f:
        csr_data = f.read()

    # Пробуем разные способы загрузки CSR
    # Способ 1: через cryptography.hazmat.primitives.serialization (новая версия)
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_x509_csr
        return load_pem_x509_csr(csr_data, default_backend())
    except (ImportError, AttributeError):
        pass

    # Способ 2: через x509 напрямую (некоторые версии)
    try:
        return x509.load_pem_x509_csr(csr_data, default_backend())
    except AttributeError:
        pass

    # Способ 3: старый способ (устаревший)
    try:
        return x509.load_pem_x509_certificate_request(csr_data, default_backend())
    except AttributeError:
        pass

    # Если ничего не сработало, выдаем ошибку
    raise RuntimeError("Cannot load CSR: no suitable method found. Please update cryptography.")


def verify_csr(csr: x509.CertificateSigningRequest) -> bool:
    """
    Verify CSR signature.

    Args:
        csr: CertificateSigningRequest object

    Returns:
        True if signature is valid
    """
    try:
        public_key = csr.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm
            )
        else:
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                ec.ECDSA(csr.signature_hash_algorithm)
            )
        return True
    except Exception:
        return False


def extract_csr_info(csr: x509.CertificateSigningRequest) -> dict:
    """
    Extract information from CSR for logging.

    Args:
        csr: CertificateSigningRequest object

    Returns:
        Dictionary with CSR information
    """
    info = {
        'subject': csr.subject.rfc4514_string(),
        'public_key_type': type(csr.public_key()).__name__,
    }

    # Extract extensions
    for extension in csr.extensions:
        if extension.oid == x509.oid.ExtensionOID.BASIC_CONSTRAINTS:
            info['is_ca'] = extension.value.ca
            info['path_length'] = extension.value.path_length
        elif extension.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            sans = []
            for san in extension.value:
                if isinstance(san, x509.DNSName):
                    sans.append(f"dns:{san.value}")
                elif isinstance(san, x509.IPAddress):
                    sans.append(f"ip:{san.value}")
                elif isinstance(san, x509.RFC822Name):
                    sans.append(f"email:{san.value}")
                elif isinstance(san, x509.UniformResourceIdentifier):
                    sans.append(f"uri:{san.value}")
            info['sans'] = sans

    return info