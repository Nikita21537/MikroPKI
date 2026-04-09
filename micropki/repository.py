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

    def __init__(self, *args, db=None, cert_dir=None, **kwargs):
        self.db = db
        self.cert_dir = Path(cert_dir) if cert_dir else None
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):

        logger.info(f"[HTTP] {self.address_string()} - {format % args}")

    def send_json_error(self, status_code: int, message: str):
        self.send_response(status_code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(message.encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path


        if path.startswith('/certificate/'):
            serial = path.split('/')[-1]
            self.handle_get_certificate(serial)


        elif path.startswith('/ca/'):
            ca_type = path.split('/')[-1]
            self.handle_get_ca(ca_type)

        # GET /crl
        elif path == '/crl':
            self.handle_get_crl()

        # GET /health (optional)
        elif path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'OK')

        else:
            self.send_json_error(404, f"Endpoint not found: {path}")

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

    def handle_get_crl(self):

        self.send_response(501)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b"CRL generation not yet implemented")
        logger.info("CRL endpoint accessed (not implemented)")

    def do_OPTIONS(self):

        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()


class RepositoryServer:
    def __init__(self, host: str, port: int, db, cert_dir: str):
        self.host = host
        self.port = port
        self.db = db
        self.cert_dir = cert_dir
        self.server = None

    def start(self):


        def handler(*args, **kwargs):
            PKIHTTPHandler(*args, db=self.db, cert_dir=self.cert_dir, **kwargs)

        self.server = HTTPServer((self.host, self.port), handler)
        logger.info(f"Repository server starting on http://{self.host}:{self.port}")

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
            self.server.shutdown()