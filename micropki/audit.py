import json
import os
import fcntl
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:

    timestamp: str
    level: str
    operation: str
    status: str
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    integrity: Optional[Dict[str, str]] = None


class AuditLogger:


    def __init__(self, log_path: Path, chain_path: Optional[Path] = None):

        self.log_path = Path(log_path)
        if chain_path is None:
            self.chain_path = self.log_path.parent / f"{self.log_path.stem}.chain"
        else:
            self.chain_path = Path(chain_path)

        self._ensure_directories()
        self._last_hash = self._load_last_hash()
        self._lock_file = None

    def _ensure_directories(self) -> None:

        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _acquire_lock(self):

        self._lock_file = open(self.log_path, 'a')
        fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX)

    def _release_lock(self):

        if self._lock_file:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
            self._lock_file.close()
            self._lock_file = None

    def _load_last_hash(self) -> str:

        if self.chain_path.exists():
            try:
                with open(self.chain_path, 'r') as f:
                    return f.read().strip()
            except Exception:
                pass
        return "0" * 64

    def _save_last_hash(self, hash_value: str) -> None:

        with open(self.chain_path, 'w') as f:
            f.write(hash_value)

    def _compute_entry_hash(self, entry_dict: Dict[str, Any]) -> str:

        # Create a copy without integrity.hash
        entry_copy = json.loads(json.dumps(entry_dict, sort_keys=True))
        if 'integrity' in entry_copy and 'hash' in entry_copy['integrity']:
            # Remove the hash field for computation
            del entry_copy['integrity']['hash']

        # Sort keys for deterministic JSON
        canonical_json = json.dumps(entry_copy, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical_json.encode()).hexdigest()

    def log(self, entry: AuditEntry) -> bool:

        try:
            # Convert to dict
            entry_dict = asdict(entry)

            # Add integrity with prev_hash
            entry_dict['integrity'] = {
                'prev_hash': self._last_hash,
                'hash': ''  # Placeholder
            }

            # Compute hash
            entry_hash = self._compute_entry_hash(entry_dict)
            entry_dict['integrity']['hash'] = entry_hash

            # Acquire lock for append
            self._acquire_lock()

            try:
                # Append to log file
                with open(self.log_path, 'a') as f:
                    f.write(json.dumps(entry_dict, sort_keys=True) + '\n')

                # Update chain file
                self._save_last_hash(entry_hash)
                self._last_hash = entry_hash

                return True
            finally:
                self._release_lock()

        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
            return False

    def log_event(
            self,
            operation: str,
            status: str,
            message: str,
            level: str = "AUDIT",
            metadata: Optional[Dict[str, Any]] = None
    ) -> bool:

        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level,
            operation=operation,
            status=status,
            message=message,
            metadata=metadata or {}
        )
        return self.log(entry)

    def verify_integrity(self) -> Tuple[bool, List[str]]:

        errors = []

        if not self.log_path.exists():
            return True, []  # Empty log is valid

        prev_hash = "0" * 64
        line_num = 0

        try:
            with open(self.log_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError as e:
                        errors.append(f"Line {line_num}: Invalid JSON - {e}")
                        continue

                    # Check integrity field
                    if 'integrity' not in entry:
                        errors.append(f"Line {line_num}: Missing integrity field")
                        continue

                    stored_prev_hash = entry['integrity'].get('prev_hash')
                    stored_hash = entry['integrity'].get('hash')

                    if stored_prev_hash != prev_hash:
                        errors.append(
                            f"Line {line_num}: Hash chain broken. "
                            f"Expected prev_hash={prev_hash}, got {stored_prev_hash}"
                        )

                    # Recompute hash
                    computed_hash = self._compute_entry_hash(entry)
                    if computed_hash != stored_hash:
                        errors.append(
                            f"Line {line_num}: Hash mismatch. Entry may be tampered."
                        )

                    prev_hash = stored_hash

            # Verify against chain file
            if self.chain_path.exists():
                with open(self.chain_path, 'r') as f:
                    chain_hash = f.read().strip()
                if chain_hash != prev_hash:
                    errors.append(
                        f"Chain file mismatch. Expected {prev_hash}, got {chain_hash}"
                    )

        except Exception as e:
            errors.append(f"Verification failed: {e}")

        return len(errors) == 0, errors

    def query(
            self,
            from_time: Optional[datetime] = None,
            to_time: Optional[datetime] = None,
            level: Optional[str] = None,
            operation: Optional[str] = None,
            serial: Optional[str] = None,
            limit: int = 1000
    ) -> List[Dict[str, Any]]:

        results = []

        if not self.log_path.exists():
            return results

        with open(self.log_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Apply filters
                if from_time:
                    entry_time = datetime.fromisoformat(entry.get('timestamp', ''))
                    if entry_time < from_time:
                        continue

                if to_time:
                    entry_time = datetime.fromisoformat(entry.get('timestamp', ''))
                    if entry_time > to_time:
                        continue

                if level and entry.get('level') != level:
                    continue

                if operation and entry.get('operation') != operation:
                    continue

                if serial:
                    meta_serial = entry.get('metadata', {}).get('serial', '')
                    if serial.upper() not in meta_serial.upper():
                        continue

                results.append(entry)
                if len(results) >= limit:
                    break

        return results


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> Optional[AuditLogger]:

    return _audit_logger


def init_audit_system(out_dir: Path) -> AuditLogger:

    global _audit_logger
    audit_dir = out_dir / "audit"
    log_path = audit_dir / "audit.log"
    _audit_logger = AuditLogger(log_path)


    _audit_logger.log_event(
        operation="audit_init",
        status="success",
        message="Audit system initialized",
        metadata={
            "log_path": str(log_path),
            "chain_path": str(_audit_logger.chain_path)
        }
    )

    return _audit_logger


def log_audit_event(
        operation: str,
        status: str,
        message: str,
        level: str = "AUDIT",
        metadata: Optional[Dict[str, Any]] = None
) -> bool:

    if _audit_logger:
        return _audit_logger.log_event(operation, status, message, level, metadata)
    return False