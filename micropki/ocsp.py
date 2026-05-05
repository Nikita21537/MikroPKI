import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List, Dict, Any
from enum import IntEnum

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    OCSPResponseBuilder,
    OCSPResponseStatus,
    load_der_ocsp_request,
)
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class OCSPCertStatus(IntEnum):
    GOOD = 0
    REVOKED = 1
    UNKNOWN = 2


class OCSPError(Exception):
    pass


class MalformedRequestError(OCSPError):
    pass


class OCSPResponder:
    def __init__(
            self,
            responder_cert: x509.Certificate,
            responder_key,
            ca_cert: x509.Certificate,
            db,
            cache_ttl: int = 60,
            logger_instance=None
    ):
        self.responder_cert = responder_cert
        self.responder_key = responder_key
        self.ca_cert = ca_cert
        self.db = db
        self.cache_ttl = cache_ttl
        self.logger = logger_instance or logger

        self._issuer_name_hash = self._compute_issuer_name_hash()
        self._issuer_key_hash = self._compute_issuer_key_hash()
        self._cache: Dict[str, Tuple[bytes, datetime]] = {}

    def _compute_issuer_name_hash(self) -> bytes:
        subject_der = self.ca_cert.subject.public_bytes(serialization.Encoding.DER)
        digest = hashes.Hash(hashes.SHA1(), default_backend())
        digest.update(subject_der)
        return digest.finalize()

    def _compute_issuer_key_hash(self) -> bytes:
        public_key_der = self.ca_cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(hashes.SHA1(), default_backend())
        digest.update(public_key_der)
        return digest.finalize()

    def verify_issuer_match(self, name_hash: bytes, key_hash: bytes) -> bool:
        return name_hash == self._issuer_name_hash and key_hash == self._issuer_key_hash

    def _get_certificate_status(self, serial_hex: str, issuer_name: str) -> Tuple[
        OCSPCertStatus, Optional[datetime], Optional[str]]:
        cert = self.db.get_certificate_by_serial(serial_hex)

        if cert is None or cert['issuer'] != issuer_name:
            return OCSPCertStatus.UNKNOWN, None, None

        if cert['status'] == 'revoked':
            rev_date = None
            if cert.get('revocation_date'):
                try:
                    rev_date = datetime.fromisoformat(cert['revocation_date'])
                    if rev_date.tzinfo is not None:
                        rev_date = rev_date.replace(tzinfo=None)
                except (ValueError, TypeError):
                    rev_date = datetime.now(timezone.utc).replace(tzinfo=None)
            reason = cert.get('revocation_reason', 'unspecified')
            return OCSPCertStatus.REVOKED, rev_date, reason

        return OCSPCertStatus.GOOD, None, None

    def _get_responder_id_by_key_hash(self) -> bytes:
        public_key_der = self.responder_cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(hashes.SHA1(), default_backend())
        digest.update(public_key_der)
        return digest.finalize()

    def parse_request(self, request_data: bytes) -> Dict[str, Any]:
        try:
            ocsp_request = load_der_ocsp_request(request_data)

            parsed = {
                'requests': [],
                'nonce': None,
            }

            # Iterate through requests in OCSP request
            for req in ocsp_request:
                parsed['requests'].append({
                    'hash_algorithm': req.hash_algorithm.name if hasattr(req, 'hash_algorithm') else "SHA1",
                    'issuer_name_hash': req.issuer_name_hash,
                    'issuer_key_hash': req.issuer_key_hash,
                    'serial_number': req.serial_number,
                    'serial_hex': format(req.serial_number, 'X').upper().lstrip('0') or '0',
                })

            # Try to get extensions
            try:
                if hasattr(ocsp_request, 'extensions') and ocsp_request.extensions:
                    for ext in ocsp_request.extensions:
                        if ext.oid.dotted_string == "1.3.6.1.5.5.7.48.1.2":
                            parsed['nonce'] = ext.value
            except:
                pass

            return parsed

        except Exception as e:
            self.logger.error(f"Failed to parse OCSP request: {e}")
            raise MalformedRequestError(f"Malformed OCSP request: {e}")

    def build_response(self, parsed_request: Dict[str, Any], issuer_name: str) -> bytes:
        produced_at = datetime.now(timezone.utc).replace(tzinfo=None)
        next_update = produced_at + timedelta(seconds=self.cache_ttl)

        builder = OCSPResponseBuilder()

        for req_info in parsed_request['requests']:
            status, rev_date, reason = self._get_certificate_status(
                req_info['serial_hex'], issuer_name
            )

            if status == OCSPCertStatus.GOOD:
                builder = builder.add_certificate_response(
                    req_info['serial_number'],
                    issuer_name_hash=req_info['issuer_name_hash'],
                    issuer_key_hash=req_info['issuer_key_hash'],
                    hash_algorithm=hashes.SHA1(),
                    cert_status=OCSPResponseStatus.SUCCESSFUL,
                    this_update=produced_at,
                    next_update=next_update,
                    revocation_time=None,
                    revocation_reason=None,
                )
            elif status == OCSPCertStatus.REVOKED:
                builder = builder.add_certificate_response(
                    req_info['serial_number'],
                    issuer_name_hash=req_info['issuer_name_hash'],
                    issuer_key_hash=req_info['issuer_key_hash'],
                    hash_algorithm=hashes.SHA1(),
                    cert_status=OCSPResponseStatus.REVOKED,
                    this_update=produced_at,
                    next_update=next_update,
                    revocation_time=rev_date or produced_at,
                    revocation_reason=reason if reason != 'unspecified' else None,
                )
            else:
                builder = builder.add_certificate_response(
                    req_info['serial_number'],
                    issuer_name_hash=req_info['issuer_name_hash'],
                    issuer_key_hash=req_info['issuer_key_hash'],
                    hash_algorithm=hashes.SHA1(),
                    cert_status=OCSPResponseStatus.UNAUTHORIZED,
                    this_update=produced_at,
                    next_update=next_update,
                    revocation_time=None,
                    revocation_reason=None,
                )

        builder = builder.responder_id(
            OCSPResponseBuilder.RESPONDER_ID_KEY_HASH,
            self._get_responder_id_by_key_hash()
        )
        builder = builder.produced_at(produced_at)

        if parsed_request.get('nonce'):
            builder = builder.add_extension(x509.extensions.Extension(
                oid=x509.oid.ExtensionOID.from_dotted_string("1.3.6.1.5.5.7.48.1.2"),
                critical=False,
                value=parsed_request['nonce']
            ))

        if isinstance(self.responder_key, rsa.RSAPrivateKey):
            response = builder.sign(self.responder_key, hashes.SHA256(), default_backend())
        else:
            response = builder.sign(self.responder_key, hashes.SHA384(), default_backend())

        return response.public_bytes(serialization.Encoding.DER)

    def handle_request(self, request_data: bytes) -> Tuple[bytes, int]:
        try:
            parsed = self.parse_request(request_data)

            if not parsed['requests']:
                self.logger.warning("OCSP request with no certificate requests")
                return self._build_error_response(OCSPResponseStatus.MALFORMED_REQUEST), 200

            first_req = parsed['requests'][0]
            if not self.verify_issuer_match(first_req['issuer_name_hash'], first_req['issuer_key_hash']):
                self.logger.warning("Unauthorized issuer")
                return self._build_error_response(OCSPResponseStatus.UNAUTHORIZED), 200

            issuer_name = self.ca_cert.subject.rfc4514_string()
            response_data = self.build_response(parsed, issuer_name)

            self.logger.info(f"OCSP response generated: requests={len(parsed['requests'])}")
            return response_data, 200

        except MalformedRequestError as e:
            self.logger.error(f"Malformed OCSP request: {e}")
            return self._build_error_response(OCSPResponseStatus.MALFORMED_REQUEST), 200
        except Exception as e:
            self.logger.error(f"Internal error: {e}", exc_info=True)
            return self._build_error_response(OCSPResponseStatus.INTERNAL_ERROR), 500

    def _build_error_response(self, status: int) -> bytes:
        builder = OCSPResponseBuilder()
        builder = builder.responder_id(
            OCSPResponseBuilder.RESPONDER_ID_KEY_HASH,
            self._get_responder_id_by_key_hash()
        )
        builder = builder.produced_at(datetime.now(timezone.utc).replace(tzinfo=None))

        try:
            response = builder.sign(self.responder_key, hashes.SHA256(), default_backend())
            return response.public_bytes(serialization.Encoding.DER)
        except:
            # Fallback: return minimal response
            return b''


def create_ocsp_signing_certificate(
        issuer_cert: x509.Certificate,
        issuer_key,
        subject_dn: str,
        validity_days: int,
        key_type: str = "rsa",
        key_size: int = 2048,
        san_list: Optional[List[str]] = None,
        ocsp_url: Optional[str] = None
) -> Tuple[x509.Certificate, any]:
    from .certificates import parse_dn_string
    from .crypto_utils import generate_rsa_key, generate_ecc_key, generate_serial_number
    from . import templates

    if key_type == "rsa":
        private_key = generate_rsa_key(key_size)
    else:
        private_key = generate_ecc_key(key_size)

    public_key = private_key.public_key()
    subject = parse_dn_string(subject_dn)
    serial_number = generate_serial_number()

    not_valid_before = datetime.now(timezone.utc).replace(tzinfo=None)
    not_valid_after = not_valid_before + timedelta(days=validity_days)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    from cryptography.x509.oid import ExtendedKeyUsageOID
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
        critical=False
    )

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(ski, critical=False)

    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key())
    builder = builder.add_extension(aki, critical=False)

    if san_list:
        san_ext = templates.build_san_extension(san_list, "client")
        builder = builder.add_extension(san_ext, critical=False)

    if ocsp_url:
        from cryptography.x509.oid import AuthorityInformationAccessOID
        aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier(ocsp_url)
            )
        ])
        builder = builder.add_extension(aia, critical=False)

    if isinstance(issuer_key, rsa.RSAPrivateKey):
        certificate = builder.sign(issuer_key, hashes.SHA256(), default_backend())
    else:
        certificate = builder.sign(issuer_key, hashes.SHA384(), default_backend())

    return certificate, private_key