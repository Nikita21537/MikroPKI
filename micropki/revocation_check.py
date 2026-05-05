import logging
import requests
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple, Dict, Any
from enum import Enum
from urllib.parse import urlparse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    OCSPResponseStatus,
    load_der_ocsp_response,
)

logger = logging.getLogger(__name__)


class RevocationStatus(Enum):
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    ERROR = "error"


class CRLChecker:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def check_certificate(
            self,
            cert: x509.Certificate,
            issuer: x509.Certificate,
            crl_source: Optional[str] = None
    ) -> Tuple[RevocationStatus, Optional[Dict[str, Any]]]:
        crl_data = self._fetch_crl(cert, crl_source)
        if crl_data is None:
            return RevocationStatus.UNKNOWN, {'error': 'Could not fetch CRL'}

        try:
            crl = x509.load_pem_x509_crl(crl_data, default_backend())
        except:
            try:
                crl = x509.load_der_x509_crl(crl_data, default_backend())
            except Exception as e:
                return RevocationStatus.UNKNOWN, {'error': f'Failed to parse CRL: {e}'}

        # Verify CRL signature
        try:
            issuer_public_key = issuer.public_key()
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    crl.signature,
                    crl.tbs_certlist_bytes,
                    padding.PKCS1v15(),
                    crl.signature_hash_algorithm
                )
            else:
                issuer_public_key.verify(
                    crl.signature,
                    crl.tbs_certlist_bytes,
                    ec.ECDSA(crl.signature_hash_algorithm)
                )
        except Exception as e:
            return RevocationStatus.UNKNOWN, {'error': f'CRL signature verification failed: {e}'}

        # Check CRL freshness
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if crl.next_update and crl.next_update.replace(tzinfo=None) < now:
            logger.warning(f"CRL is expired (next_update={crl.next_update})")

        # Look for certificate serial
        serial_int = cert.serial_number
        for revoked in crl:
            if revoked.serial_number == serial_int:
                reason = None
                for ext in revoked.extensions:
                    if ext.oid.dotted_string == "2.5.29.21":
                        try:
                            reason = ext.value.dotted_string if hasattr(ext.value, 'dotted_string') else str(ext.value)
                        except:
                            reason = "unspecified"

                rev_date = revoked.revocation_date
                if rev_date and hasattr(rev_date, 'tzinfo') and rev_date.tzinfo is not None:
                    rev_date = rev_date.replace(tzinfo=None)

                return RevocationStatus.REVOKED, {
                    'revocation_date': rev_date.isoformat() if rev_date else None,
                    'reason': reason,
                }

        return RevocationStatus.GOOD, {}

    def _fetch_crl(self, cert: x509.Certificate, crl_source: Optional[str]) -> Optional[bytes]:
        if crl_source:
            return self._fetch_from_source(crl_source)

        try:
            cdp_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            for point in cdp_ext.value:
                for name in point.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        crl_source = name.value
                        logger.info(f"Found CRL in CDP: {crl_source}")
                        return self._fetch_from_source(crl_source)
        except x509.extensions.ExtensionNotFound:
            pass

        return None

    def _fetch_from_source(self, source: str) -> Optional[bytes]:
        parsed = urlparse(source)
        if parsed.scheme in ('http', 'https'):
            try:
                response = requests.get(source, timeout=self.timeout)
                response.raise_for_status()
                return response.content
            except Exception as e:
                logger.error(f"Failed to fetch CRL from {source}: {e}")
                return None
        else:
            path = Path(source)
            if path.exists():
                with open(path, 'rb') as f:
                    return f.read()
            logger.error(f"CRL file not found: {source}")
            return None


class OCSPChecker:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def check_certificate(
            self,
            cert: x509.Certificate,
            issuer: x509.Certificate,
            responder_url: Optional[str] = None,
            use_nonce: bool = True
    ) -> Tuple[RevocationStatus, Optional[Dict[str, Any]]]:
        if responder_url is None:
            responder_url = self._extract_ocsp_url(cert)

        if responder_url is None:
            return RevocationStatus.UNKNOWN, {'error': 'No OCSP responder URL available'}

        try:
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer, hashes.SHA1())
            request = builder.build()
            request_der = request.public_bytes(serialization.Encoding.DER)
        except Exception as e:
            return RevocationStatus.ERROR, {'error': f'Failed to build OCSP request: {e}'}

        try:
            response = requests.post(
                responder_url,
                data=request_der,
                headers={'Content-Type': 'application/ocsp-request'},
                timeout=self.timeout
            )
            response.raise_for_status()
        except Exception as e:
            return RevocationStatus.UNKNOWN, {'error': f'OCSP request failed: {e}'}

        try:
            ocsp_response = load_der_ocsp_response(response.content)
        except Exception as e:
            return RevocationStatus.ERROR, {'error': f'Failed to parse OCSP response: {e}'}

        if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
            return RevocationStatus.UNKNOWN, {'error': f'OCSP response status: {ocsp_response.response_status}'}

        for single_response in ocsp_response.responses:
            status = single_response.certificate_status
            if status == OCSPResponseStatus.GOOD:
                return RevocationStatus.GOOD, {}
            elif status == OCSPResponseStatus.REVOKED:
                rev_time = single_response.revocation_time
                if rev_time and hasattr(rev_time, 'tzinfo') and rev_time.tzinfo is not None:
                    rev_time = rev_time.replace(tzinfo=None)
                return RevocationStatus.REVOKED, {
                    'revocation_time': rev_time.isoformat() if rev_time else None,
                }

        return RevocationStatus.UNKNOWN, {'error': 'No response for requested certificate'}

    def _extract_ocsp_url(self, cert: x509.Certificate) -> Optional[str]:
        try:
            aia_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            for desc in aia_ext.value:
                if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        return desc.access_location.value
        except x509.extensions.ExtensionNotFound:
            pass
        return None


class RevocationChecker:
    def __init__(self, timeout: int = 10, cache_ttl: int = 60):
        self.ocsp_checker = OCSPChecker(timeout)
        self.crl_checker = CRLChecker(timeout)
        self.cache = {}
        self.cache_ttl = cache_ttl

    def check_certificate_status(
            self,
            cert: x509.Certificate,
            issuer: x509.Certificate,
            ocsp_url: Optional[str] = None,
            crl_source: Optional[str] = None,
            prefer_ocsp: bool = True
    ) -> RevocationStatus:
        cache_key = (format(cert.serial_number, 'X'), issuer.subject.rfc4514_string())
        if cache_key in self.cache:
            status, timestamp = self.cache[cache_key]
            if (datetime.now(timezone.utc) - timestamp).total_seconds() < self.cache_ttl:
                logger.debug(f"Cache hit for {cache_key[0]}")
                return status

        if prefer_ocsp:
            status, details = self.ocsp_checker.check_certificate(cert, issuer, ocsp_url)
            logger.info(f"OCSP check result: {status.value} - {details}")

            if status in (RevocationStatus.GOOD, RevocationStatus.REVOKED):
                self._cache_result(cache_key, status)
                return status

            logger.info("OCSP failed/unknown, falling back to CRL")
            status, details = self.crl_checker.check_certificate(cert, issuer, crl_source)
            logger.info(f"CRL check result: {status.value} - {details}")
        else:
            status, details = self.crl_checker.check_certificate(cert, issuer, crl_source)
            logger.info(f"CRL check result: {status.value} - {details}")

            if status in (RevocationStatus.GOOD, RevocationStatus.REVOKED):
                self._cache_result(cache_key, status)
                return status

            logger.info("CRL failed, falling back to OCSP")
            status, details = self.ocsp_checker.check_certificate(cert, issuer, ocsp_url)
            logger.info(f"OCSP check result: {status.value} - {details}")

        self._cache_result(cache_key, status)
        return status

    def _cache_result(self, key, status: RevocationStatus):
        self.cache[key] = (status, datetime.now(timezone.utc))

    def clear_cache(self):
        self.cache.clear()