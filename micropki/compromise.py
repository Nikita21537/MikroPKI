import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Any
import sqlite3

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from .database import Database
from .certificates import load_certificate
from .revocation import RevocationManager, RevocationReason
from .audit import log_audit_event


def compute_public_key_hash(certificate: x509.Certificate) -> str:

    public_key = certificate.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_key_der).hexdigest()


def compute_public_key_hash_from_private(private_key) -> str:

    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_key_der).hexdigest()


class CompromiseManager:

    def __init__(self, db: Database, out_dir: Path):

        self.db = db
        self.out_dir = Path(out_dir)
        self._init_compromised_table()

    def _init_compromised_table(self) -> None:

        conn = self.db._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compromised_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_key_hash TEXT UNIQUE NOT NULL,
                certificate_serial TEXT NOT NULL,
                compromise_date TEXT NOT NULL,
                compromise_reason TEXT NOT NULL
            )
        """)

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_public_key_hash ON compromised_keys(public_key_hash)"
        )

        conn.commit()
        conn.close()

    def mark_compromised(
            self,
            certificate: x509.Certificate,
            reason: str = "keyCompromise"
    ) -> Tuple[bool, str]:

        serial_hex = format(certificate.serial_number, '016X')
        public_key_hash = compute_public_key_hash(certificate)

        conn = self.db._get_connection()
        cursor = conn.cursor()

        try:
            # Check if already compromised
            cursor.execute(
                "SELECT id FROM compromised_keys WHERE public_key_hash = ?",
                (public_key_hash,)
            )
            if cursor.fetchone():
                conn.close()
                return True, f"Key already marked as compromised"

            # Insert into compromised_keys table
            cursor.execute("""
                INSERT INTO compromised_keys
                (public_key_hash, certificate_serial, compromise_date, compromise_reason)
                VALUES (?, ?, ?, ?)
            """, (
                public_key_hash,
                serial_hex,
                datetime.now(timezone.utc).isoformat(),
                reason
            ))

            conn.commit()
            conn.close()

            # Log audit event
            log_audit_event(
                operation="key_compromise",
                status="success",
                message=f"Private key marked as compromised for certificate {serial_hex}",
                metadata={
                    "serial": serial_hex,
                    "subject": certificate.subject.rfc4514_string(),
                    "reason": reason
                }
            )

            return True, f"Key marked as compromised"

        except Exception as e:
            conn.close()
            return False, f"Failed to mark key as compromised: {e}"

    def is_key_compromised(self, certificate: x509.Certificate) -> bool:

        public_key_hash = compute_public_key_hash(certificate)
        return self.is_public_key_compromised(public_key_hash)

    def is_public_key_compromised(self, public_key_hash: str) -> bool:

        conn = self.db._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM compromised_keys WHERE public_key_hash = ?",
            (public_key_hash,)
        )
        result = cursor.fetchone()
        conn.close()

        return result is not None

    def get_compromised_keys(self) -> List[Dict[str, Any]]:

        conn = self.db._get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM compromised_keys ORDER BY compromise_date DESC")
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def revoke_and_compromise(
            self,
            cert_path: Path,
            reason: str = "keyCompromise",
            force: bool = False
    ) -> Tuple[bool, str]:

        # Load certificate
        try:
            certificate = load_certificate(cert_path)
        except Exception as e:
            return False, f"Failed to load certificate: {e}"

        serial_hex = format(certificate.serial_number, '016X')

        # Revoke the certificate
        revoke_mgr = RevocationManager(self.db, self.out_dir)
        success, message = revoke_mgr.revoke_certificate(serial_hex, reason, force)

        if not success:
            return False, f"Revocation failed: {message}"

        # Mark key as compromised
        self.mark_compromised(certificate, reason)

        # Generate emergency CRL
        try:
            from .revocation import CRLManager
            crl_mgr = CRLManager(self.out_dir, self.db)

            # Determine CA type
            cert_record = self.db.get_certificate_by_serial(serial_hex)
            if cert_record:
                issuer = cert_record.get('issuer', '')
                root_cert_path = self.out_dir / "certs" / "ca.cert.pem"
                if root_cert_path.exists():
                    root_cert = load_certificate(root_cert_path)
                    if root_cert.subject.rfc4514_string() == issuer:
                        ca_type = "root"
                    else:
                        ca_type = "intermediate"
                else:
                    ca_type = "intermediate"

                # Find passphrase file
                pass_file = self.out_dir.parent / "secrets" / f"{ca_type}.pass"

                ca_cert_path = self.out_dir / "certs" / f"{ca_type}.cert.pem"
                ca_key_path = self.out_dir / "private" / f"{ca_type}.key.pem"

                if ca_cert_path.exists() and ca_key_path.exists() and pass_file.exists():
                    crl_mgr.generate_crl(
                        ca_cert_path=ca_cert_path,
                        ca_key_path=ca_key_path,
                        ca_pass_file=pass_file,
                        ca_type=ca_type,
                        next_update_days=7
                    )
        except Exception as e:

            pass

        return True, f"Certificate revoked and key marked as compromised"


class CompromiseChecker:


    def __init__(self, compromise_manager: CompromiseManager):

        self.compromise_manager = compromise_manager

    def check_csr_for_compromise(self, public_key) -> Tuple[bool, str]:

        try:
            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_hash = hashlib.sha256(public_key_der).hexdigest()
        except Exception as e:
            return False, f"Failed to compute public key hash: {e}"

        if self.compromise_manager.is_public_key_compromised(public_key_hash):
            return False, "This public key has been marked as compromised. Issuance blocked."

        return True, ""

    def check_certificate_for_compromise(self, certificate: x509.Certificate) -> bool:

        return self.compromise_manager.is_key_compromised(certificate)