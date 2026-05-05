from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import hashlib
import threading


class CTLog:


    def __init__(self, log_path: Path):

        self.log_path = Path(log_path)
        self._lock = threading.Lock()
        self._ensure_directory()

    def _ensure_directory(self) -> None:

        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_certificate(
            self,
            serial: str,
            subject: str,
            fingerprint: str,
            issuer: Optional[str] = None
    ) -> bool:

        timestamp = datetime.now(timezone.utc).isoformat()
        entry = f"{timestamp} | {serial} | {subject} | {fingerprint}"
        if issuer:
            entry += f" | {issuer}"
        entry += "\n"

        with self._lock:
            try:
                with open(self.log_path, 'a') as f:
                    f.write(entry)
                return True
            except Exception:
                return False

    def verify_inclusion(self, serial: str) -> bool:

        if not self.log_path.exists():
            return False

        with self._lock:
            with open(self.log_path, 'r') as f:
                for line in f:
                    if f" | {serial} | " in line:
                        return True
        return False

    def get_all_entries(self) -> List[Dict[str, str]]:

        entries = []

        if not self.log_path.exists():
            return entries

        with self._lock:
            with open(self.log_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split(' | ')
                    if len(parts) >= 4:
                        entries.append({
                            'timestamp': parts[0],
                            'serial': parts[1],
                            'subject': parts[2],
                            'fingerprint': parts[3],
                            'issuer': parts[4] if len(parts) > 4 else None
                        })

        return entries



_ct_log: Optional[CTLog] = None


def init_ct_log(out_dir: Path) -> CTLog:

    global _ct_log
    audit_dir = out_dir / "audit"
    _ct_log = CTLog(audit_dir / "ct.log")
    return _ct_log


def get_ct_log() -> Optional[CTLog]:

    return _ct_log


def log_certificate_to_ct(
        serial: str,
        subject: str,
        fingerprint: str,
        issuer: Optional[str] = None
) -> bool:

    if _ct_log:
        return _ct_log.log_certificate(serial, subject, fingerprint, issuer)
    return False