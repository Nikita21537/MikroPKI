import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone
from micropki.database import Database


@pytest.fixture
def temp_db():


    # Используем NamedTemporaryFile с delete=False для Windows
    fd = None
    try:
        fd, path = tempfile.mkstemp(suffix='.db')
        # Закрываем файловый дескриптор сразу после создания пути
        if fd:
            import os
            os.close(fd)
            fd = None

        db = Database(path)
        yield db, path

    finally:
        # Очистка после теста
        import os
        if fd is not None:
            os.close(fd)
        try:
            if 'path' in locals() and os.path.exists(path):
                os.unlink(path)
        except (PermissionError, OSError):
            # На Windows может потребоваться дополнительная задержка
            import time
            time.sleep(0.1)
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except PermissionError:
                pass


def test_db_init(temp_db):
    db, path = temp_db
    assert Path(path).exists()


def test_insert_and_retrieve_certificate(temp_db):
    db, _ = temp_db

    cert_data = {
        'serial_hex': '1234567890ABCDEF',
        'subject': 'CN=Test',
        'issuer': 'CN=Root CA',
        'not_before': datetime.now(timezone.utc).isoformat(),
        'not_after': datetime.now(timezone.utc).isoformat(),
        'cert_pem': '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        'status': 'valid',
        'created_at': datetime.now(timezone.utc).isoformat()
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
            'not_before': datetime.now(timezone.utc).isoformat(),
            'not_after': datetime.now(timezone.utc).isoformat(),
            'cert_pem': 'test',
            'status': 'valid',
            'created_at': datetime.now(timezone.utc).isoformat()
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
        'not_before': datetime.now(timezone.utc).isoformat(),
        'not_after': datetime.now(timezone.utc).isoformat(),
        'cert_pem': 'test',
        'status': 'valid',
        'created_at': datetime.now(timezone.utc).isoformat()
    }

    assert db.insert_certificate(cert_data) is True
    assert db.insert_certificate(cert_data) is False  # Duplicate


def test_serial_counter(temp_db):
    db, _ = temp_db

    serial1 = db.get_next_serial_counter()
    serial2 = db.get_next_serial_counter()

    assert serial2 == serial1 + 1