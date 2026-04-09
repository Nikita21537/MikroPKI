from typing import List, Optional
from ipaddress import ip_address




from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec


class CertificateTemplate:


    def __init__(self, name: str):
        self.name = name

    def get_key_usage(self) -> x509.KeyUsage:

        raise NotImplementedError

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:

        raise NotImplementedError

    def validate_sans(self, san_list: List[str]) -> None:

        pass

    def get_basic_constraints(self) -> x509.BasicConstraints:

        return x509.BasicConstraints(ca=False, path_length=None)


class ServerTemplate(CertificateTemplate):


    def __init__(self):
        super().__init__("server")

    def get_key_usage(self) -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,  # For RSA
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])

    def validate_sans(self, san_list: List[str]) -> None:

        if not san_list:
            raise ValueError("Server certificate must have at least one SAN (DNS or IP)")

        has_valid_san = False
        for san in san_list:
            if san.startswith('dns:') or san.startswith('ip:'):
                has_valid_san = True
            elif san.startswith('email:') or san.startswith('uri:'):
                raise ValueError(f"Server certificate does not support {san.split(':')[0]} SAN type")

        if not has_valid_san:
            raise ValueError("Server certificate must have at least one DNS or IP SAN")


class ClientTemplate(CertificateTemplate):


    def __init__(self):
        super().__init__("client")

    def get_key_usage(self) -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,  # For ECDH
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])

    def validate_sans(self, san_list: List[str]) -> None:

        for san in san_list:
            san_type = san.split(':')[0]
            if san_type not in ['dns', 'email']:
                raise ValueError(f"Client certificate supports only DNS and email SAN types, got {san_type}")


class CodeSigningTemplate(CertificateTemplate):
    """Code signing certificate template."""

    def __init__(self):
        super().__init__("code_signing")

    def get_key_usage(self) -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def get_extended_key_usage(self) -> x509.ExtendedKeyUsage:
        return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])

    def validate_sans(self, san_list: List[str]) -> None:

        for san in san_list:
            san_type = san.split(':')[0]
            if san_type not in ['dns', 'uri']:
                raise ValueError(f"Code signing certificate supports only DNS and URI SAN types, got {san_type}")


def get_template(template_name: str) -> CertificateTemplate:

    templates = {
        'server': ServerTemplate,
        'client': ClientTemplate,
        'code_signing': CodeSigningTemplate,
    }

    if template_name not in templates:
        raise ValueError(f"Unknown template: {template_name}. Available: {', '.join(templates.keys())}")

    return templates[template_name]()


def build_san_extension(san_list: List[str], template_name: str) -> x509.SubjectAlternativeName:


    general_names = []

    for san in san_list:
        if ':' not in san:
            raise ValueError(f"Invalid SAN format: {san}. Expected 'type:value'")

        san_type, san_value = san.split(':', 1)

        if san_type == 'dns':
            general_names.append(x509.DNSName(san_value))
        elif san_type == 'ip':
            try:
                ip = ip_address(san_value)
                general_names.append(x509.IPAddress(ip))
            except ValueError:
                raise ValueError(f"Invalid IP address: {san_value}")
        elif san_type == 'email':
            general_names.append(x509.RFC822Name(san_value))
        elif san_type == 'uri':
            general_names.append(x509.UniformResourceIdentifier(san_value))
        else:
            raise ValueError(f"Unsupported SAN type: {san_type}. Supported: dns, ip, email, uri")


    template = get_template(template_name)
    template.validate_sans(san_list)

    return x509.SubjectAlternativeName(general_names)