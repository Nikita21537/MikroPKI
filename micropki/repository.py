from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

from .ratelimit import get_rate_limiter

logger = logging.getLogger(__name__)


class PKIHTTPHandler(BaseHTTPRequestHandler):

    server_version = "MicroPKI/1.0"

    def __init__(self, *args, db=None, cert_dir=None, out_dir=None, **kwargs):
        self.db = db
        self.cert_dir = Path(cert_dir) if cert_dir else None
        self.out_dir = Path(out_dir) if out_dir else None
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
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(b'Rate limit exceeded. Please try again later.')
                logger.warning(f"Rate limit exceeded for {client_ip}")
                return False
        return True

    def log_message(self, format, *args):
        logger.info(f"[HTTP] {self.address_string()} - {format % args}")

    def send_json_error(self, status_code: int, message: str):
        self.send_response(status_code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(message.encode())

    def send_crl_response(self, crl_path: Path):
        if not crl_path.exists():
            self.send_json_error(404, f"CRL not found: {crl_path.name}")
            return

        with open(crl_path, 'rb') as f:
            crl_content = f.read()

        self.send_response(200)
        self.send_header('Content-Type', 'application/pkix-crl')
        self.send_header('Access-Control-Allow-Origin', '*')

        stat = crl_path.stat()
        self.send_header('Last-Modified', self.date_time_string(stat.st_mtime))
        self.send_header('Cache-Control', 'max-age=3600')

        etag = f'"{stat.st_size}-{stat.st_mtime}"'
        self.send_header('ETag', etag)

        self.end_headers()
        self.wfile.write(crl_content)
        logger.info(f"CRL served: {crl_path.name}")

    def do_GET(self):

        # Rate limiting check
        if not self._check_rate_limit():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        # CRL endpoint
        if path.startswith('/crl'):
            self.handle_crl_request(parsed)
            return

        # Certificate by serial endpoint
        if path.startswith('/certificate/'):
            serial = path.split('/')[-1]
            self.handle_get_certificate(serial)
            return

        # CA certificate endpoint
        if path.startswith('/ca/'):
            ca_type = path.split('/')[-1]
            self.handle_get_ca(ca_type)
            return

        # Health check endpoint
        if path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'OK')
            return

        # Not found
        self.send_json_error(404, f"Endpoint not found: {path}")

    def do_POST(self):

        # Rate limiting check
        if not self._check_rate_limit():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        # Request certificate endpoint (Sprint 6)
        if path == '/request-cert':
            self.handle_request_cert(parsed)
            return

        # Method not allowed for other paths
        self.send_json_error(405, "Method Not Allowed")

    def do_OPTIONS(self):

        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def handle_crl_request(self, parsed):

        query_params = parse_qs(parsed.query)

        # Determine CA type from query parameter
        ca_param = query_params.get('ca', ['intermediate'])[0]

        if ca_param not in ['root', 'intermediate']:
            self.send_json_error(400, "ca parameter must be 'root' or 'intermediate'")
            return

        if not self.out_dir:
            self.send_json_error(500, "PKI directory not configured")
            return

        crl_path = self.out_dir / "crl" / f"{ca_param}.crl.pem"
        self.send_crl_response(crl_path)

    def handle_get_certificate(self, serial: str):

        # Validate serial format (hex)
        try:
            if not all(c in '0123456789ABCDEFabcdef' for c in serial):
                raise ValueError("Invalid hex characters")
            int(serial, 16)
        except ValueError:
            self.send_json_error(400, "Invalid serial number format. Expected hexadecimal.")
            return

        # Query database
        cert_record = self.db.get_certificate_by_serial(serial.upper())

        if cert_record:
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-pem-file')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(cert_record['cert_pem'].encode())
            logger.info(f"Certificate served: {serial}")
        else:
            self.send_json_error(404, f"Certificate with serial {serial} not found")

    def handle_get_ca(self, ca_type: str):

        if ca_type not in ['root', 'intermediate']:
            self.send_json_error(400, "CA type must be 'root' or 'intermediate'")
            return

        if not self.cert_dir:
            self.send_json_error(500, "Certificate directory not configured")
            return

        # Try standard naming
        cert_file = self.cert_dir / f"{ca_type}.cert.pem"

        # Fallback to alternative naming
        if not cert_file.exists():
            cert_file = self.cert_dir / f"{ca_type}_ca.pem"

        if cert_file.exists():
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-pem-file')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            with open(cert_file, 'rb') as f:
                self.wfile.write(f.read())
            logger.info(f"CA certificate served: {ca_type}")
        else:
            self.send_json_error(404, f"{ca_type} CA certificate not found")

    def handle_request_cert(self, parsed):

        from .intermediate import IssueCertificate
        from .crypto_utils import load_passphrase
        import tempfile

        # Parse query parameters
        query_params = parse_qs(parsed.query)
        template = query_params.get('template', ['server'])[0]

        if template not in ['server', 'client', 'code_signing']:
            self.send_json_error(400, f"Invalid template: {template}")
            return

        # Get request body (CSR in PEM format)
        content_type = self.headers.get('Content-Type', '')
        if content_type != 'application/x-pem-file':
            self.send_json_error(400, "Expected Content-Type: application/x-pem-file")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_json_error(400, "Empty request body")
            return

        csr_data = self.rfile.read(content_length)

        # Save CSR to temporary file
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csr', delete=False) as f:
            f.write(csr_data)
            csr_path = Path(f.name)

        try:
            # Find CA credentials
            ca_cert_path = self.cert_dir / "intermediate.cert.pem"
            if not ca_cert_path.exists():
                ca_cert_path = self.cert_dir / "ca.cert.pem"

            ca_key_path = self.out_dir / "private" / "intermediate.key.pem"
            if not ca_key_path.exists():
                ca_key_path = self.out_dir / "private" / "ca.key.pem"

            # Find passphrase file
            pass_file = self.out_dir.parent / "secrets" / "intermediate.pass"
            if not pass_file.exists():
                pass_file = self.out_dir.parent / "secrets" / "root.pass"
            if not pass_file.exists():
                pass_file = self.out_dir.parent / "secrets" / "ca.pass"

            if not ca_cert_path.exists() or not ca_key_path.exists() or not pass_file.exists():
                self.send_json_error(500, "CA not properly configured")
                return

            # Issue certificate
            issuer = IssueCertificate()
            cert_path, _ = issuer.issue_certificate(
                ca_cert_path=ca_cert_path,
                ca_key_path=ca_key_path,
                ca_pass_file=pass_file,
                template_name=template,
                subject_dn="",  # Will be taken from CSR
                san_list=[],  # Will be taken from CSR
                out_dir=self.out_dir / "certs",
                validity_days=365,
                csr_path=csr_path
            )

            # Read and return certificate
            with open(cert_path, 'rb') as f:
                cert_pem = f.read()

            self.send_response(201)
            self.send_header('Content-Type', 'application/x-pem-file')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(cert_pem)

            logger.info(f"Certificate issued via API: {cert_path.name}")

        except Exception as e:
            logger.error(f"Certificate issuance failed: {e}")
            self.send_json_error(500, f"Certificate issuance failed: {e}")
        finally:
            # Clean up temporary file
            if csr_path.exists():
                csr_path.unlink()


class RepositoryServer:
    def __init__(self, host: str, port: int, db, cert_dir: str, out_dir: Path = None):

        self.host = host
        self.port = port
        self.db = db
        self.cert_dir = cert_dir
        self.out_dir = out_dir or Path("./pki")
        self.server = None

    def start(self):

        def handler(*args, **kwargs):
            PKIHTTPHandler(*args, db=self.db, cert_dir=self.cert_dir, out_dir=self.out_dir, **kwargs)

        self.server = HTTPServer((self.host, self.port), handler)

        # Log server startup
        logger.info("=" * 60)
        logger.info(f"Repository server starting on http://{self.host}:{self.port}")
        logger.info(f"  Certificate directory: {self.cert_dir}")
        logger.info(f"  CRL directory: {self.out_dir / 'crl'}")
        logger.info(f"  Endpoints:")
        logger.info(f"    GET  /certificate/<serial>  - Fetch certificate by serial")
        logger.info(f"    GET  /ca/root               - Fetch Root CA certificate")
        logger.info(f"    GET  /ca/intermediate       - Fetch Intermediate CA certificate")
        logger.info(f"    GET  /crl?ca=root           - Fetch Root CRL")
        logger.info(f"    GET  /crl?ca=intermediate   - Fetch Intermediate CRL")
        logger.info(f"    POST /request-cert          - Submit CSR for signing")
        logger.info(f"    GET  /health                - Health check")
        logger.info("=" * 60)

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
            self.server.shutdown()