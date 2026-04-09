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

    from .certificates import parse_dn_string

    subject = parse_dn_string(subject_dn)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)

    if san_list:
        san_ext = templates.build_san_extension(san_list, template_name)
        builder = builder.add_extension(san_ext, critical=False)

    if pathlen is not None:

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=pathlen),
            critical=True
        )


    if isinstance(private_key, rsa.RSAPrivateKey):
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    else:
        csr = builder.sign(private_key, hashes.SHA384(), default_backend())

    return csr


def save_csr(csr: x509.CertificateSigningRequest, csr_path: Path) -> None:

    csr_path.parent.mkdir(parents=True, exist_ok=True)

    with open(csr_path, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def load_csr(csr_path: Path) -> x509.CertificateSigningRequest:

    with open(csr_path, 'rb') as f:
        csr_data = f.read()

    try:
        from cryptography.hazmat.primitives.serialization import load_pem_x509_csr
        return load_pem_x509_csr(csr_data, default_backend())
    except (ImportError, AttributeError):
        pass

    try:
        return x509.load_pem_x509_csr(csr_data, default_backend())
    except AttributeError:
        pass

    try:
        return x509.load_pem_x509_certificate_request(csr_data, default_backend())
    except AttributeError:
        pass

    raise RuntimeError("Cannot load CSR: no suitable method found. Please update cryptography.")


def verify_csr(csr: x509.CertificateSigningRequest) -> bool:

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

    info = {
        'subject': csr.subject.rfc4514_string(),
        'public_key_type': type(csr.public_key()).__name__,
    }

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