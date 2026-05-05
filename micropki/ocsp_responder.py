import logging
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .ocsp import OCSPResponder
from .database import Database
from .certificates import load_certificate
from .logger import setup_logger
from .ratelimit import get_rate_limiter
from .audit import log_audit_event

logger = logging.getLogger(__name__)


class OCSPHTTPHandler(BaseHTTPRequestHandler):


    server_version = "MicroPKI-OCSP/1.0"

    def __init__(self, *args, responder=None, **kwargs):
        self.responder = responder
        super().__init__(*args, **kwargs)

    def _check_rate_limit(self) -> bool:
        limiter = get_rate_limiter()
        if limiter and limiter.is_enabled():
            client_ip = self.client_address[0]
            allowed, retry_after = limiter.check_request(client_ip)
            if not allowed:
                self.send_response(429)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Retry-After', str(retry_after))
                self.end_headers()
                self.wfile.write(b'Rate limit exceeded. Please try again later.')
                logger.warning(f"Rate limit exceeded for {client_ip}")
                return False
        return True

    def log_message(self, format, *args):
        logger.info(f"[OCSP] {self.address_string()} - {format % args}")

    def _send_ocsp_response(self, response_data: bytes, http_status: int = 200):
        self.send_response(http_status)
        self.send_header('Content-Type', 'application/ocsp-response')
        self.send_header('Content-Length', str(len(response_data)))
        self.end_headers()
        self.wfile.write(response_data)

    def _send_error_response(self, status_code: int, message: str):

        self.send_response(status_code)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(message.encode())

    def do_GET(self):

        # Rate limiting check
        if not self._check_rate_limit():
            return

        parsed = urlparse(self.path)

        if parsed.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
            return

        self._send_error_response(404, "Not found. Use POST /ocsp for OCSP requests.")

    def do_POST(self):
        # Rate limiting check
        if not self._check_rate_limit():
            return

        parsed = urlparse(self.path)

        if parsed.path != '/ocsp':
            self._send_error_response(404, "Not found. Use /ocsp endpoint.")
            return

        content_type = self.headers.get('Content-Type', '')
        if content_type.lower() != 'application/ocsp-request':
            self._send_error_response(400, "Expected Content-Type: application/ocsp-request")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self._send_error_response(400, "Empty request body")
            return

        request_data = self.rfile.read(content_length)
        start_time = time.time()
        client_ip = self.client_address[0]

        try:
            response_data, http_status = self.responder.handle_request(request_data)
            elapsed_ms = (time.time() - start_time) * 1000
            logger.info(f"OCSP request from {client_ip}: elapsed_ms={elapsed_ms:.2f}")
            self._send_ocsp_response(response_data, http_status)
        except Exception as e:
            logger.error(f"OCSP request failed: {e}")
            self._send_error_response(500, f"Internal server error: {e}")


class OCSPResponderServer:

    def __init__(
            self,
            host: str,
            port: int,
            db_path: str,
            responder_cert_path: Path,
            responder_key_path: Path,
            ca_cert_path: Path,
            cache_ttl: int = 60,
            log_file: Optional[str] = None
    ):

        self.host = host
        self.port = port
        self.db_path = db_path
        self.responder_cert_path = Path(responder_cert_path)
        self.responder_key_path = Path(responder_key_path)
        self.ca_cert_path = Path(ca_cert_path)
        self.cache_ttl = cache_ttl
        self.log_file = log_file
        self.server = None
        self.responder = None

        self.logger = setup_logger(log_file)

    def _load_certificates_and_key(self):
        responder_cert = load_certificate(self.responder_cert_path)

        with open(self.responder_key_path, 'rb') as f:
            key_data = f.read()
        responder_key = serialization.load_pem_private_key(
            key_data, password=None, backend=default_backend()
        )

        ca_cert = load_certificate(self.ca_cert_path)
        db = Database(self.db_path)

        return responder_cert, responder_key, ca_cert, db

    def start(self):
        self.logger.info("Loading certificates and database...")

        try:
            responder_cert, responder_key, ca_cert, db = self._load_certificates_and_key()
        except Exception as e:
            self.logger.error(f"Failed to load certificates: {e}")
            raise

        self.responder = OCSPResponder(
            responder_cert=responder_cert,
            responder_key=responder_key,
            ca_cert=ca_cert,
            db=db,
            cache_ttl=self.cache_ttl,
            logger_instance=self.logger
        )

        def handler(*args, **kwargs):
            OCSPHTTPHandler(*args, responder=self.responder, **kwargs)

        self.server = HTTPServer((self.host, self.port), handler)

        # Log startup
        self.logger.info("=" * 60)
        self.logger.info(f"OCSP Responder starting on http://{self.host}:{self.port}")
        self.logger.info(f"  OCSP endpoint: POST http://{self.host}:{self.port}/ocsp")
        self.logger.info(f"  Health check:  GET http://{self.host}:{self.port}/health")

        # Log rate limiting status
        limiter = get_rate_limiter()
        if limiter and limiter.is_enabled():
            self.logger.info(f"  Rate limiting: enabled ({limiter.rate} req/s, burst {limiter.burst})")
        else:
            self.logger.info("  Rate limiting: disabled")

        self.logger.info("=" * 60)

        # Log audit event
        log_audit_event(
            "ocsp_responder_start",
            "success",
            f"OCSP responder started on {self.host}:{self.port}",
            metadata={"host": self.host, "port": self.port}
        )

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            self.logger.info("OCSP Responder stopped by user")
            log_audit_event("ocsp_responder_stop", "success", "OCSP responder stopped")
            self.server.shutdown()