from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class PKIHTTPHandler(BaseHTTPRequestHandler):
    server_version = "MicroPKI/1.0"

    def __init__(self, *args, db=None, cert_dir=None, out_dir=None, **kwargs):
        self.db = db
        self.cert_dir = Path(cert_dir) if cert_dir else None
        self.out_dir = Path(out_dir) if out_dir else None
        super().__init__(*args, **kwargs)

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

        # Добавляем заголовки кэширования
        stat = crl_path.stat()
        self.send_header('Last-Modified', self.date_time_string(stat.st_mtime))
        self.send_header('Cache-Control', 'max-age=3600')  # 1 hour

        # ETag на основе размера и времени модификации
        etag = f'"{stat.st_size}-{stat.st_mtime}"'
        self.send_header('ETag', etag)

        self.end_headers()
        self.wfile.write(crl_content)
        logger.info(f"CRL served: {crl_path.name}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Sprint 4: CRL endpoints
        if path.startswith('/crl'):
            self.handle_crl_request(parsed)
            return

        # Certificate endpoints
        if path.startswith('/certificate/'):
            serial = path.split('/')[-1]
            self.handle_get_certificate(serial)
            return

        # CA endpoints
        if path.startswith('/ca/'):
            ca_type = path.split('/')[-1]
            self.handle_get_ca(ca_type)
            return

        # Health endpoint
        if path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'OK')
            return

        self.send_json_error(404, f"Endpoint not found: {path}")

    def handle_crl_request(self, parsed):

        query_params = parse_qs(parsed.query)

        # Определяем какой CRL запрошен
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
        # Validate hex format
        try:
            if not all(c in '0123456789ABCDEFabcdef' for c in serial):
                raise ValueError("Invalid hex characters")
            int(serial, 16)
        except ValueError:
            self.send_json_error(400, "Invalid serial number format. Expected hexadecimal.")
            return

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

        cert_file = self.cert_dir / f"{ca_type}.cert.pem"

        # Also try alternative naming
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

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()


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
        logger.info(f"Repository server starting on http://{self.host}:{self.port}")
        logger.info(f"CRL directory: {self.out_dir / 'crl'}")

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
            self.server.shutdown()