import pytest
import tempfile

import shutil
from pathlib import Path
from datetime import datetime
from micropki.database import Database


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix='.db')
    db = Database(path)
    yield db, path
    import os
    os.close(fd)
    os.unlink(path)


def test_db_init(temp_db):
    db, path = temp_db
    assert Path(path).exists()


def test_insert_and_retrieve_certificate(temp_db):
    db, _ = temp_db

    cert_data = {
        'serial_hex': '1234567890ABCDEF',
        'subject': 'CN=Test',
        'issuer': 'CN=Root CA',
        'not_before': datetime.utcnow().isoformat(),
        'not_after': datetime.utcnow().isoformat(),
        'cert_pem': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        'status': 'valid',
        'created_at': datetime.utcnow().isoformat()
    }

    assert db.insert_certificate(cert_data) is True

    retrieved = db.get_certificate_by_serial('1234567890ABCDEF')
    assert retrieved is not None
    assert retrieved['subject'] == 'CN=Test'


def test_list_certificates(temp_db):
    db, _ = temp_db

    for i in range(3):
        cert_data = {
            'serial_hex': f'SERIAL{i:02X}',
            'subject': f'CN=Test{i}',
            'issuer': 'CN=Root',
            'not_before': datetime.utcnow().isoformat(),
            'not_after': datetime.utcnow().isoformat(),
            'cert_pem': 'test',
            'status': 'valid',
            'created_at': datetime.utcnow().isoformat()
        }
        db.insert_certificate(cert_data)

    certs = db.list_certificates(limit=10)
    assert len(certs) >= 3


def test_duplicate_serial_prevention(temp_db):
    db, _ = temp_db

    cert_data = {
        'serial_hex': 'DUPLICATE',
        'subject': 'CN=Test',
        'issuer': 'CN=Root',
        'not_before': datetime.utcnow().isoformat(),
        'not_after': datetime.utcnow().isoformat(),
        'cert_pem': 'test',
        'status': 'valid',
        'created_at': datetime.utcnow().isoformat()
    }

    assert db.insert_certificate(cert_data) is True
    assert db.insert_certificate(cert_data) is False  # Duplicate


def test_serial_counter(temp_db):
    db, _ = temp_db

    serial1 = db.get_next_serial_counter()
    serial2 = db.get_next_serial_counter()

    assert serial2 == serial1 + 1