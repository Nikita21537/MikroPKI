import pytest

from micropki.serial import SerialGenerator


class MockDB:
    def __init__(self):
        self.counter = 1000
        self.certs = {}

    def get_next_serial_counter(self):
        self.counter += 1
        return self.counter

    def get_certificate_by_serial(self, serial):
        return self.certs.get(serial)


def test_serial_generator():
    mock_db = MockDB()
    gen = SerialGenerator(mock_db, use_counter=True)

    serials = set()
    for _ in range(100):
        serial = gen.generate_serial()
        assert len(serial) == 16  # 16 hex chars = 64 bits
        assert all(c in '0123456789ABCDEF' for c in serial)
        serials.add(serial)

    # Все серийные номера должны быть уникальными
    assert len(serials) == 100


def test_serial_uniqueness_validation():
    mock_db = MockDB()
    gen = SerialGenerator(mock_db, use_counter=True)

    # Добавляем тестовый сертификат
    mock_db.certs['0000000000000001'] = {}

    assert gen.validate_serial_uniqueness('0000000000000001') is False
    assert gen.validate_serial_uniqueness('0000000000000002') is True