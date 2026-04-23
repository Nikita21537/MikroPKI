from enum import IntEnum
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
import logging


from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .database import Database
from .certificates import load_certificate, parse_dn_string
from .crypto_utils import load_encrypted_private_key, load_passphrase

logger = logging.getLogger(__name__)


class RevocationReason(IntEnum):

    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10

    @classmethod
    def from_string(cls, reason_str: str) -> Optional["RevocationReason"]:

        mapping = {
            "unspecified": cls.UNSPECIFIED,
            "keycompromise": cls.KEY_COMPROMISE,
            "cacompromise": cls.CA_COMPROMISE,
            "affiliationchanged": cls.AFFILIATION_CHANGED,
            "superseded": cls.SUPERSEDED,
            "cessationofoperation": cls.CESSATION_OF_OPERATION,
            "certificatehold": cls.CERTIFICATE_HOLD,
            "removefromcrl": cls.REMOVE_FROM_CRL,
            "privilegewithdrawn": cls.PRIVILEGE_WITHDRAWN,
            "aacompromise": cls.AA_COMPROMISE,
        }
        return mapping.get(reason_str.lower())

    def to_string(self) -> str:
        """Преобразует枚举 в строковое представление."""
        mapping = {
            self.UNSPECIFIED: "unspecified",
            self.KEY_COMPROMISE: "keyCompromise",
            self.CA_COMPROMISE: "cACompromise",
            self.AFFILIATION_CHANGED: "affiliationChanged",
            self.SUPERSEDED: "superseded",
            self.CESSATION_OF_OPERATION: "cessationOfOperation",
            self.CERTIFICATE_HOLD: "certificateHold",
            self.REMOVE_FROM_CRL: "removeFromCRL",
            self.PRIVILEGE_WITHDRAWN: "privilegeWithdrawn",
            self.AA_COMPROMISE: "aACompromise",
        }
        return mapping.get(self, "unspecified")


class CRLManager:


    def __init__(self, out_dir: Path, db: Database, logger_instance=None):
        self.out_dir = Path(out_dir)
        self.crl_dir = self.out_dir / "crl"
        self.db = db
        self.logger = logger_instance or logger

    def _ensure_crl_dir(self) -> None:

        self.crl_dir.mkdir(mode=0o755, parents=True, exist_ok=True)

    def _get_crl_number(self, ca_subject: str) -> int:

        conn = self.db._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
            (ca_subject,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return row[0] + 1
        return 1

    def _update_crl_metadata(
        self,
        ca_subject: str,
        crl_number: int,
        next_update: datetime,
        crl_path: Path
    ) -> None:

        conn = self.db._get_connection()
        cursor = conn.cursor()

        now = datetime.now(timezone.utc).isoformat()

        cursor.execute("""
            INSERT OR REPLACE INTO crl_metadata
            (ca_subject, crl_number, last_generated, next_update, crl_path)
            VALUES (?, ?, ?, ?, ?)
        """, (
            ca_subject,
            crl_number,
            now,
            next_update.isoformat(),
            str(crl_path.relative_to(self.out_dir))
        ))

        conn.commit()
        conn.close()
        self.logger.info(f"CRL metadata updated for {ca_subject}: number={crl_number}")

    def get_revoked_certificates_for_issuer(
        self,
        issuer_subject: str
    ) -> List[Dict[str, Any]]:

        conn = self.db._get_connection()
        conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT serial_hex, revocation_date, revocation_reason
            FROM certificates
            WHERE issuer = ? AND status = 'revoked'
            ORDER BY revocation_date DESC
        """, (issuer_subject,))

        results = cursor.fetchall()
        conn.close()

        return results

    def generate_crl(
        self,
        ca_cert_path: Path,
        ca_key_path: Path,
        ca_pass_file: Path,
        ca_type: str,
        next_update_days: int = 7,
        out_file: Optional[Path] = None
    ) -> Path:

        self._ensure_crl_dir()

        self.logger.info(f"Generating CRL for {ca_type} CA")

        # Загрузка сертификата CA
        ca_cert = load_certificate(ca_cert_path)
        ca_subject = ca_cert.subject.rfc4514_string()

        # Загрузка закрытого ключа CA
        ca_pass = load_passphrase(ca_pass_file)
        ca_key = load_encrypted_private_key(ca_key_path, ca_pass)

        # Получение отозванных сертификатов
        revoked_certs = self.get_revoked_certificates_for_issuer(ca_subject)
        self.logger.info(f"Found {len(revoked_certs)} revoked certificates for {ca_subject}")

        # Получение номера CRL
        crl_number = self._get_crl_number(ca_subject)

        # Создание CRL с помощью cryptography
        now = datetime.now(timezone.utc)
        next_update = now + timedelta(days=next_update_days)

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(next_update)

        # Добавление отозванных сертификатов
        for revoked in revoked_certs:
            try:
                serial_int = int(revoked['serial_hex'], 16)

                revoked_builder = x509.RevokedCertificateBuilder()
                revoked_builder = revoked_builder.serial_number(serial_int)

                # Парсим дату отзыва
                rev_date = datetime.fromisoformat(revoked['revocation_date'])
                revoked_builder = revoked_builder.revocation_date(rev_date)

                # Добавляем причину отзыва если есть
                reason_str = revoked.get('revocation_reason')
                if reason_str:
                    reason_enum = RevocationReason.from_string(reason_str)
                    if reason_enum is not None:
                        revoked_builder = revoked_builder.add_extension(
                            x509.CRLReason(reason_enum.value),
                            critical=False
                        )

                revoked_cert = revoked_builder.build(default_backend())
                builder = builder.add_revoked_certificate(revoked_cert)

            except Exception as e:
                self.logger.warning(f"Failed to add revoked cert {revoked['serial_hex']}: {e}")

        # Добавление расширений CRL
        # Authority Key Identifier
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
        builder = builder.add_extension(aki, critical=False)

        # CRL Number
        builder = builder.add_extension(
            x509.CRLNumber(crl_number),
            critical=False
        )

        # Подпись CRL
        if isinstance(ca_key, rsa.RSAPrivateKey):
            crl = builder.sign(
                private_key=ca_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
        else:
            crl = builder.sign(
                private_key=ca_key,
                algorithm=hashes.SHA384(),
                backend=default_backend()
            )

        # Определение пути сохранения
        if out_file is None:
            out_file = self.crl_dir / f"{ca_type}.crl.pem"
        else:
            out_file = Path(out_file)

        # Сохранение CRL в PEM формате
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, 'wb') as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        # Обновление метаданных
        self._update_crl_metadata(ca_subject, crl_number, next_update, out_file)

        self.logger.info(
            f"CRL generated successfully: {out_file} "
            f"(number={crl_number}, revoked={len(revoked_certs)})"
        )

        return out_file

    def get_crl_path(self, ca_type: str) -> Optional[Path]:
        crl_path = self.crl_dir / f"{ca_type}.crl.pem"
        if crl_path.exists():
            return crl_path
        return None

    def get_crl_content(self, ca_type: str) -> Optional[bytes]:

        crl_path = self.get_crl_path(ca_type)
        if crl_path:
            with open(crl_path, 'rb') as f:
                return f.read()
        return None


class RevocationManager:


    def __init__(self, db: Database, out_dir: Path, logger_instance=None):
        self.db = db
        self.out_dir = Path(out_dir)
        self.crl_manager = CRLManager(out_dir, db, logger_instance)
        self.logger = logger_instance or logger

    def revoke_certificate(
        self,
        serial_hex: str,
        reason: Optional[str] = None,
        force: bool = False
    ) -> Tuple[bool, str]:

        serial_hex = serial_hex.upper()

        # Поиск сертификата
        cert = self.db.get_certificate_by_serial(serial_hex)
        if cert is None:
            msg = f"Certificate with serial {serial_hex} not found"
            self.logger.error(msg)
            return False, msg

        # Проверка статуса
        if cert['status'] == 'revoked':
            msg = f"Certificate {serial_hex} is already revoked"
            self.logger.warning(msg)
            return True, msg

        # Подтверждение если не force
        if not force:
            print(f"Certificate to revoke:")
            print(f"  Subject: {cert['subject']}")
            print(f"  Issuer: {cert['issuer']}")
            print(f"  Serial: {serial_hex}")
            if reason:
                print(f"  Reason: {reason}")

            response = input("\nAre you sure you want to revoke this certificate? [y/N]: ")
            if response.lower() not in ['y', 'yes']:
                msg = "Revocation cancelled"
                self.logger.info(msg)
                return False, msg

        # Обновление статуса в БД
        success = self.db.update_certificate_status(
            serial_hex,
            'revoked',
            revocation_reason=reason
        )

        if not success:
            msg = f"Failed to update certificate status for {serial_hex}"
            self.logger.error(msg)
            return False, msg

        self.logger.info(f"Certificate {serial_hex} revoked successfully (reason: {reason})")

        # Определяем тип CA для обновления CRL
        issuer = cert['issuer']
        ca_type = self._determine_ca_type(issuer)

        # Автоматически обновляем CRL после отзыва
        try:
            self.logger.info(f"Auto-generating CRL for {ca_type} CA")
            self.generate_crl_for_issuer(issuer, ca_type)
        except Exception as e:
            self.logger.warning(f"Failed to auto-generate CRL: {e}")
            msg = f"Certificate revoked but CRL generation failed: {e}"
            return True, msg

        return True, f"Certificate {serial_hex} revoked successfully"

    def _determine_ca_type(self, issuer_subject: str) -> str:

        # Проверяем наличие корневого сертификата
        root_cert_path = self.out_dir / "certs" / "ca.cert.pem"
        if root_cert_path.exists():
            root_cert = load_certificate(root_cert_path)
            if root_cert.subject.rfc4514_string() == issuer_subject:
                return "root"

        return "intermediate"

    def generate_crl_for_issuer(
        self,
        issuer_subject: str,
        ca_type: str,
        next_update_days: int = 7
    ) -> Optional[Path]:

        # Определяем пути к файлам CA
        if ca_type == "root":
            ca_cert_path = self.out_dir / "certs" / "ca.cert.pem"
            ca_key_path = self.out_dir / "private" / "ca.key.pem"
        else:
            ca_cert_path = self.out_dir / "certs" / "intermediate.cert.pem"
            ca_key_path = self.out_dir / "private" / "intermediate.key.pem"

        # Поиск файла с паролем
        pass_file = self.out_dir.parent / "secrets" / f"{ca_type}.pass"
        if not pass_file.exists():
            # Альтернативные пути
            alt_pass_file = self.out_dir.parent / "secrets" / f"{ca_type}_pass.txt"
            if alt_pass_file.exists():
                pass_file = alt_pass_file
            else:
                self.logger.error(f"Passphrase file not found for {ca_type} CA")
                return None

        if not ca_cert_path.exists():
            self.logger.error(f"CA certificate not found: {ca_cert_path}")
            return None

        if not ca_key_path.exists():
            self.logger.error(f"CA key not found: {ca_key_path}")
            return None

        return self.crl_manager.generate_crl(
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
            ca_pass_file=pass_file,
            ca_type=ca_type,
            next_update_days=next_update_days
        )

    def check_revoked(self, serial_hex: str) -> Tuple[bool, Optional[Dict[str, Any]]]:

        serial_hex = serial_hex.upper()
        cert = self.db.get_certificate_by_serial(serial_hex)

        if cert is None:
            return False, None

        if cert['status'] == 'revoked':
            return True, {
                'serial_hex': cert['serial_hex'],
                'subject': cert['subject'],
                'revocation_date': cert['revocation_date'],
                'revocation_reason': cert['revocation_reason']
            }

        return False, None