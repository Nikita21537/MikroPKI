import sqlite3

import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_hex TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                status TEXT NOT NULL,
                revocation_reason TEXT,
                revocation_date TEXT,
                created_at TEXT NOT NULL
            )
        """)

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates(serial_hex)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)")

        # Create serial counter table for uniqueness
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS serial_counter (
                id INTEGER PRIMARY KEY,
                last_serial INTEGER
            )
        """)

        cursor.execute("INSERT OR IGNORE INTO serial_counter (id, last_serial) VALUES (1, 0)")

        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")

    def insert_certificate(self, cert_data: Dict[str, Any]) -> bool:
        """Insert a certificate into the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO certificates 
                (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cert_data['serial_hex'],
                cert_data['subject'],
                cert_data['issuer'],
                cert_data['not_before'],
                cert_data['not_after'],
                cert_data['cert_pem'],
                cert_data['status'],
                cert_data['created_at']
            ))

            conn.commit()
            conn.close()
            logger.info(f"Certificate inserted: {cert_data['serial_hex']} - {cert_data['subject']}")
            return True

        except sqlite3.IntegrityError as e:
            logger.error(f"Duplicate serial number: {e}")
            return False
        except Exception as e:
            logger.error(f"Database insertion error: {e}")
            return False

    def get_certificate_by_serial(self, serial_hex: str) -> Optional[Dict[str, Any]]:
        """Retrieve certificate by serial number"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM certificates WHERE serial_hex = ?", (serial_hex.upper(),))
            row = cursor.fetchone()

            conn.close()

            if row:
                logger.info(f"Certificate retrieved: {serial_hex}")
                return dict(row)
            else:
                logger.warning(f"Certificate not found: {serial_hex}")
                return None

        except Exception as e:
            logger.error(f"Error retrieving certificate: {e}")
            return None

    def list_certificates(self, status: Optional[str] = None,
                          issuer: Optional[str] = None,
                          limit: int = 100) -> List[Dict[str, Any]]:
        """List certificates with optional filters"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT serial_hex, subject, issuer, not_before, not_after, status, created_at FROM certificates WHERE 1=1"
            params = []

            if status:
                query += " AND status = ?"
                params.append(status)

            if issuer:
                query += " AND issuer LIKE ?"
                params.append(f"%{issuer}%")

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            conn.close()
            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error listing certificates: {e}")
            return []

    def update_certificate_status(self, serial_hex: str, status: str,
                                  revocation_reason: Optional[str] = None) -> bool:
        """Update certificate status (for future revocation)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            update_data = {
                'status': status,
                'revocation_date': datetime.utcnow().isoformat() if status == 'revoked' else None,
                'revocation_reason': revocation_reason if status == 'revoked' else None
            }

            cursor.execute("""
                UPDATE certificates 
                SET status = ?, revocation_date = ?, revocation_reason = ?
                WHERE serial_hex = ?
            """, (update_data['status'], update_data['revocation_date'],
                  update_data['revocation_reason'], serial_hex))

            conn.commit()
            conn.close()
            logger.info(f"Certificate {serial_hex} status updated to {status}")
            return True

        except Exception as e:
            logger.error(f"Error updating certificate status: {e}")
            return False

    def get_revoked_certificates(self) -> List[Dict[str, Any]]:
        """Get all revoked certificates for CRL generation"""
        return self.list_certificates(status='revoked')

    def get_next_serial_counter(self) -> int:
        """Get and increment the persistent serial counter"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("UPDATE serial_counter SET last_serial = last_serial + 1 WHERE id = 1")
            cursor.execute("SELECT last_serial FROM serial_counter WHERE id = 1")
            counter = cursor.fetchone()[0]

            conn.commit()
            conn.close()
            return counter

        except Exception as e:
            logger.error(f"Error getting serial counter: {e}")
            return int(datetime.utcnow().timestamp())