import os
import sys
import json
import logging
import requests
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple


from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from . import crypto_utils, csr as csr_module, templates
from .certificates import load_certificate, save_certificate, parse_dn_string
from .validation import PathValidator, ChainValidationResult
from .revocation_check import RevocationChecker, RevocationStatus
from .logger import setup_logger


class ClientCLI:

    def __init__(self, log_file: Optional[str] = None):
        self.logger = setup_logger(log_file)

    def generate_csr(
            self,
            subject: str,
            key_type: str = "rsa",
            key_size: int = 2048,
            san_list: Optional[List[str]] = None,
            out_key: Path = Path("./key.pem"),
            out_csr: Path = Path("./request.csr.pem")
    ) -> Tuple[Path, Path]:

        self.logger.info(f"Generating CSR for subject: {subject}")


        if key_type == "rsa" and key_size not in [2048, 4096]:
            raise ValueError(f"RSA key size must be 2048 or 4096, got {key_size}")
        if key_type == "ecc" and key_size not in [256, 384]:
            raise ValueError(f"ECC key size must be 256 or 384, got {key_size}")


        self.logger.info(f"Generating {key_type.upper()} private key (size: {key_size})")
        if key_type == "rsa":
            private_key = crypto_utils.generate_rsa_key(key_size)
        else:
            private_key = crypto_utils.generate_ecc_key(key_size)


        template_name = "server" if san_list and any(s.startswith(('dns:', 'ip:')) for s in san_list) else "client"


        self.logger.info(f"Generating CSR with template {template_name}")
        csr_obj = csr_module.generate_csr(
            private_key=private_key,
            subject_dn=subject,
            template_name=template_name,
            san_list=san_list
        )


        if not csr_module.verify_csr(csr_obj):
            raise ValueError("CSR signature verification failed")


        out_key.parent.mkdir(parents=True, exist_ok=True)
        unencrypted_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(out_key, 'wb') as f:
            f.write(unencrypted_key)


        try:
            os.chmod(out_key, 0o600)
        except Exception:
            pass


        csr_module.save_csr(csr_obj, out_csr)

        self.logger.info(f"Private key saved to: {out_key}")
        self.logger.info(f"CSR saved to: {out_csr}")

        print("\nWARNING: Private key is stored unencrypted. Ensure proper file permissions (0600).")

        return out_key, out_csr

    def request_certificate(
            self,
            csr_path: Path,
            template: str,
            ca_url: str,
            out_cert: Path = Path("./cert.pem"),
            api_key: Optional[str] = None
    ) -> Path:

        self.logger.info(f"Requesting certificate from {ca_url}")


        if not csr_path.exists():
            raise FileNotFoundError(f"CSR file not found: {csr_path}")

        with open(csr_path, 'rb') as f:
            csr_data = f.read()


        url = f"{ca_url.rstrip('/')}/request-cert"
        params = {'template': template}

        headers = {'Content-Type': 'application/x-pem-file'}
        if api_key:
            headers['X-API-Key'] = api_key

        self.logger.info(f"POST {url}?template={template}")


        try:
            response = requests.post(
                url,
                params=params,
                data=csr_data,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(f"Failed to connect to CA at {ca_url}: {e}")
        except requests.exceptions.HTTPError as e:
            raise RuntimeError(f"CA returned error: {response.status_code} - {response.text}")

        # Save certificate
        out_cert.parent.mkdir(parents=True, exist_ok=True)
        with open(out_cert, 'wb') as f:
            f.write(response.content)

        self.logger.info(f"Certificate saved to: {out_cert}")

        # Verify certificate
        cert = load_certificate(out_cert)
        self.logger.info(f"Certificate issued: serial={format(cert.serial_number, '016X')}")

        return out_cert

    def validate_chain(
            self,
            cert_path: Path,
            untrusted_paths: List[Path],
            trusted_paths: List[Path],
            crl_source: Optional[str] = None,
            ocsp_enabled: bool = False,
            mode: str = "full",
            validation_time: Optional[datetime] = None,
            intended_usage: Optional[str] = None,
            output_format: str = "text"
    ) -> ChainValidationResult:
        """
        CLI-27: Validate certificate chain.

        Args:
            cert_path: Leaf certificate path
            untrusted_paths: Intermediate certificate paths
            trusted_paths: Trusted root certificate paths
            crl_source: CRL file or URL
            ocsp_enabled: Whether to perform OCSP check
            mode: "chain" (signature/validity only) or "full" (include revocation)
            validation_time: Override validation time
            intended_usage: Expected certificate usage
            output_format: "text" or "json"

        Returns:
            ChainValidationResult
        """
        self.logger.info(f"Validating certificate: {cert_path}")

        # Load certificates
        leaf = load_certificate(cert_path)

        intermediates = []
        for p in untrusted_paths:
            if p.exists():
                if p.is_dir():
                    for cert_file in p.glob("*.pem"):
                        intermediates.append(load_certificate(cert_file))
                else:
                    intermediates.append(load_certificate(p))
            else:
                self.logger.warning(f"Untrusted certificate not found: {p}")

        trusted_roots = []
        for p in trusted_paths:
            if p.exists():
                if p.is_dir():
                    for cert_file in p.glob("*.pem"):
                        trusted_roots.append(load_certificate(cert_file))
                else:
                    trusted_roots.append(load_certificate(p))
            else:
                self.logger.warning(f"Trusted root not found: {p}")

        if not trusted_roots:
            raise ValueError("No trusted root certificates provided")

        # Create validator
        validator = PathValidator(validation_time)

        # Perform validation
        check_revocation = (mode == "full") and (crl_source or ocsp_enabled)

        revocation_checker = None
        if check_revocation:
            revocation_checker = RevocationChecker()

        result = validator.validate_chain(
            leaf=leaf,
            intermediates=intermediates,
            trusted_roots=trusted_roots,
            check_revocation=check_revocation,
            revocation_checker=revocation_checker,
            intended_usage=intended_usage  # Pass intended_usage to validator
        )

        # Output result
        if output_format == "json":
            print(json.dumps(result.to_dict(), indent=2, default=str))
        else:
            self._print_validation_result(result)

        return result

    def _print_validation_result(self, result: ChainValidationResult):

        print("\n" + "=" * 60)
        print(f"CERTIFICATE CHAIN VALIDATION")
        print("=" * 60)
        print(f"Leaf Subject: {result.leaf_subject}")
        print(f"Validation Time: {result.validation_time}")
        print("-" * 60)

        for i, cert_result in enumerate(result.chain):
            print(f"\n[{i + 1}] Certificate: {cert_result.subject}")
            print(f"    Issuer: {cert_result.issuer}")
            print(f"    Serial: {cert_result.serial}")
            print(f"    Status: {'✓ VALID' if cert_result.is_valid else '✗ INVALID'}")

            for step in cert_result.steps:
                status_char = "✓" if step.status.value == "pass" else "✗" if step.status.value == "fail" else "○"
                print(f"      {status_char} {step.name}: {step.message}")

        print("-" * 60)
        if result.revocation_status:
            print(f"Revocation Status: {result.revocation_status.value.upper()}")

        print("-" * 60)
        if result.is_valid:
            print("OVERALL RESULT: VALID ✓")
        else:
            print("OVERALL RESULT: INVALID ✗")
            for error in result.errors:
                print(f"  Error: {error}")
        print("=" * 60)

    def check_revocation_status(
            self,
            cert_path: Path,
            ca_cert_path: Path,
            crl_source: Optional[str] = None,
            ocsp_url: Optional[str] = None
    ) -> RevocationStatus:

        self.logger.info(f"Checking revocation status for: {cert_path}")

        # Load certificates
        cert = load_certificate(cert_path)
        ca_cert = load_certificate(ca_cert_path)


        checker = RevocationChecker()

        status = checker.check_certificate_status(
            cert=cert,
            issuer=ca_cert,
            ocsp_url=ocsp_url,
            crl_source=crl_source,
            prefer_ocsp=True
        )

        print("\n" + "-" * 40)
        print(f"Certificate Revocation Status")
        print("-" * 40)
        print(f"Certificate: {cert.subject.rfc4514_string()}")
        print(f"Serial: {format(cert.serial_number, '016X')}")
        print(f"Issuer: {ca_cert.subject.rfc4514_string()}")
        print(f"\nStatus: {status.value.upper()}")

        if status == RevocationStatus.REVOKED:
            print("The certificate has been revoked!")
        elif status == RevocationStatus.GOOD:
            print("The certificate is valid (not revoked).")
        elif status == RevocationStatus.UNKNOWN:
            print("Revocation status could not be determined.")
        elif status == RevocationStatus.ERROR:
            print("An error occurred while checking revocation status.")

        print("-" * 40)

        return status