import secrets
import time

from typing import Optional
import logging

logger = logging.getLogger(__name__)


class SerialGenerator:
    def __init__(self, db, use_counter: bool = True):
        self.db = db
        self.use_counter = use_counter

    def generate_serial(self) -> str:
        """
        Generate a unique 64-bit serial number.
        High 32 bits: timestamp or counter
        Low 32 bits: CSPRNG
        """
        if self.use_counter:
            # Use persistent counter from database
            high_bits = self.db.get_next_serial_counter() & 0xFFFFFFFF
        else:
            # Use timestamp
            high_bits = int(time.time()) & 0xFFFFFFFF

        # Generate 32 random bits
        low_bits = secrets.randbits(32)

        # Combine into 64-bit integer
        serial_int = (high_bits << 32) | low_bits

        # Convert to hex string (without '0x' prefix, uppercase)
        serial_hex = format(serial_int, '016X')

        logger.debug(f"Generated serial: {serial_hex}")
        return serial_hex

    def validate_serial_uniqueness(self, serial_hex: str) -> bool:
        """Validate that serial number is unique in database"""
        existing = self.db.get_certificate_by_serial(serial_hex)
        return existing is None