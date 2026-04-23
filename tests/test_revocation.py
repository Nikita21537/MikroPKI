"""
Тесты для модуля revocation (Sprint 4).
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone

from micropki.database import Database
from micropki.revocation import RevocationManager, CRLManager, RevocationReason
from micropki.certificates import load_certificate
from micropki.crypto_utils import generate_rsa_key, generate_serial_number
from micropki import certificates


@pytest.fixture
def temp_env():
    """Создаёт временное окружение для тестов."""
    path = Path(tempfile.mkdtemp())
    db_path = path / "micropki.db"
    db = Database(str(db_path))

    # Создаём тестовый корневой сертификат
    key = generate_rsa_key(2048)
    serial = generate_serial_number()
    root_cert = certificates.create_self_signed_certificate(
        private_key=key,
        subject_dn="CN=Test Root CA,O=Test",
        validity_days=365,
        serial_number=serial
    )

    # Сохраняем сертификат
    certs_dir = path / "certs"
    certs_dir.mkdir()
    cert_path = certs_dir / "ca.cert.pem"
    certificates.save_certificate(root_cert, cert_path)

    # Сохраняем ключ
    private_dir = path / "private"
    private_dir.mkdir()
    key_path = private_dir / "ca.key.pem"
    from micropki.crypto_utils import encrypt_private_key
    encrypted_key = encrypt_private_key(key, b"testpass")
    with open(key_path, 'wb') as f:
        f.write(encrypted_key)

    # Создаём файл пароля
    secrets_dir = path.parent / "secrets"
    secrets_dir.mkdir(exist_ok=True)
    pass_file = secrets_dir / "root.pass"
    pass_file.write_text("testpass\n")

    # Добавляем тестовый сертификат в БД
    cert_data = {
        'serial_hex': '1234567890ABCDEF',
        'subject': 'CN=Test Certificate,O=Test',
        'issuer': root_cert.subject.rfc4514_string(),
        'not_before': datetime.now(timezone.utc).isoformat(),
        'not_after': (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        'cert_pem': 'test',
        'status': 'valid',
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    db.insert_certificate(cert_data)

    yield {
        'path': path,
        'db': db,
        'root_cert': root_cert,
        'root_key': key,
        'pass_file': pass_file
    }

    shutil.rmtree(path)


def test_revocation_reason_mapping():
    """Тест маппинга причин отзыва."""
    # String to enum
    assert RevocationReason.from_string("keyCompromise") == RevocationReason.KEY_COMPROMISE
    assert RevocationReason.from_string("cACompromise") == RevocationReason.CA_COMPROMISE
    assert RevocationReason.from_string("superseded") == RevocationReason.SUPERSEDED
    assert RevocationReason.from_string("invalid") is None

    # Enum to string
    assert RevocationReason.KEY_COMPROMISE.to_string() == "keyCompromise"
    assert RevocationReason.CA_COMPROMISE.to_string() == "cACompromise"
    assert RevocationReason.UNSPECIFIED.to_string() == "unspecified"


def test_revoke_certificate(temp_env):
    """Тест отзыва сертификата."""
    db = temp_env['db']
    path = temp_env['path']

    revoke_mgr = RevocationManager(db, path)

    # Отзываем сертификат
    success, message = revoke_mgr.revoke_certificate(
        "1234567890ABCDEF",
        reason="keyCompromise",
        force=True
    )

    assert success is True

    # Проверяем статус в БД
    cert = db.get_certificate_by_serial("1234567890ABCDEF")
    assert cert['status'] == 'revoked'
    assert cert['revocation_reason'] == 'keyCompromise'
    assert cert['revocation_date'] is not None


def test_revoke_nonexistent_certificate(temp_env):
    """Тест отзыва несуществующего сертификата."""
    db = temp_env['db']
    path = temp_env['path']

    revoke_mgr = RevocationManager(db, path)

    success, message = revoke_mgr.revoke_certificate(
        "NONEXISTENT",
        force=True
    )

    assert success is False
    assert "not found" in message


def test_revoke_already_revoked_certificate(temp_env):
    """Тест повторного отзыва сертификата."""
    db = temp_env['db']
    path = temp_env['path']

    revoke_mgr = RevocationManager(db, path)

    # Первый отзыв
    revoke_mgr.revoke_certificate("1234567890ABCDEF", force=True)

    # Второй отзыв
    success, message = revoke_mgr.revoke_certificate(
        "1234567890ABCDEF",
        force=True
    )

    assert success is True
    assert "already revoked" in message


def test_check_revoked(temp_env):
    """Тест проверки статуса отзыва."""
    db = temp_env['db']
    path = temp_env['path']

    revoke_mgr = RevocationManager(db, path)

    # Проверяем до отзыва
    is_revoked, info = revoke_mgr.check_revoked("1234567890ABCDEF")
    assert is_revoked is False
    assert info is None

    # Отзываем
    revoke_mgr.revoke_certificate("1234567890ABCDEF", reason="superseded", force=True)

    # Проверяем после отзыва
    is_revoked, info = revoke_mgr.check_revoked("1234567890ABCDEF")
    assert is_revoked is True
    assert info is not None
    assert info['revocation_reason'] == 'superseded'


def test_crl_generation(temp_env):
    """Тест генерации CRL."""
    db = temp_env['db']
    path = temp_env['path']

    # Отзываем сертификат
    revoke_mgr = RevocationManager(db, path)
    revoke_mgr.revoke_certificate("1234567890ABCDEF", reason="keyCompromise", force=True)

    # Генерируем CRL
    crl_mgr = CRLManager(path, db)

    ca_cert_path = path / "certs" / "ca.cert.pem"
    ca_key_path = path / "private" / "ca.key.pem"

    crl_path = crl_mgr.generate_crl(
        ca_cert_path=ca_cert_path,
        ca_key_path=ca_key_path,
        ca_pass_file=temp_env['pass_file'],
        ca_type="root",
        next_update_days=7
    )

    assert crl_path.exists()
    assert crl_path.parent == path / "crl"
    assert crl_path.name == "root.crl.pem"

    # Проверяем содержимое CRL через OpenSSL если доступен
    import subprocess
    try:
        result = subprocess.run(
            ["openssl", "crl", "-inform", "PEM", "-in", str(crl_path), "-text", "-noout"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "1234567890ABCDEF" in result.stdout.upper() or "1234567890abcdef" in result.stdout.lower()
    except FileNotFoundError:
        pytest.skip("OpenSSL not available for CRL verification")


def test_crl_metadata_persistence(temp_env):
    """Тест сохранения метаданных CRL."""
    db = temp_env['db']
    path = temp_env['path']
    crl_mgr = CRLManager(path, db)

    ca_cert_path = path / "certs" / "ca.cert.pem"
    ca_key_path = path / "private" / "ca.key.pem"

    # Генерируем первый CRL
    crl_mgr.generate_crl(
        ca_cert_path=ca_cert_path,
        ca_key_path=ca_key_path,
        ca_pass_file=temp_env['pass_file'],
        ca_type="root"
    )

    # Генерируем второй CRL
    crl_mgr.generate_crl(
        ca_cert_path=ca_cert_path,
        ca_key_path=ca_key_path,
        ca_pass_file=temp_env['pass_file'],
        ca_type="root"
    )

    # Проверяем что номер CRL увеличился
    conn = db._get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
        (temp_env['root_cert'].subject.rfc4514_string(),)
    )
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == 2  # Второй CRL должен иметь номер 2


def test_crl_with_multiple_revoked_certs(temp_env):
    """Тест CRL с несколькими отозванными сертификатами."""
    db = temp_env['db']
    path = temp_env['path']

    # Добавляем несколько тестовых сертификатов
    issuer = temp_env['root_cert'].subject.rfc4514_string()

    for i in range(3):
        cert_data = {
            'serial_hex': f'SERIAL{i:02X}',
            'subject': f'CN=Test{i},O=Test',
            'issuer': issuer,
            'not_before': datetime.now(timezone.utc).isoformat(),
            'not_after': (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            'cert_pem': 'test',
            'status': 'valid',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        db.insert_certificate(cert_data)

    # Отзываем два сертификата
    revoke_mgr = RevocationManager(db, path)
    revoke_mgr.revoke_certificate("SERIAL00", reason="keyCompromise", force=True)
    revoke_mgr.revoke_certificate("SERIAL01", reason="superseded", force=True)

    # Генерируем CRL
    crl_mgr = CRLManager(path, db)
    ca_cert_path = path / "certs" / "ca.cert.pem"
    ca_key_path = path / "private" / "ca.key.pem"

    crl_path = crl_mgr.generate_crl(
        ca_cert_path=ca_cert_path,
        ca_key_path=ca_key_path,
        ca_pass_file=temp_env['pass_file'],
        ca_type="root"
    )

    assert crl_path.exists()

    # Проверяем через OpenSSL количество отозванных
    import subprocess
    try:
        result = subprocess.run(
            ["openssl", "crl", "-inform", "PEM", "-in", str(crl_path), "-text", "-noout"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        # В выводе должно быть 2 отозванных сертификата
        assert result.stdout.count("Serial Number") >= 2
    except FileNotFoundError:
        pytest.skip("OpenSSL not available for CRL verification")