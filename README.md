# MikroPKI
Минимальная инфраструктура открытых ключей (Public Key Infrastructure) для создания самоподписанных корневых удостоверяющих центров.

## Описание

MicroPKI - это легковесный инструмент для создания и управления корневыми удостоверяющими центрами (Root CA) с поддержкой RSA и ECC ключей, безопасным хранением закрытых ключей и генерацией X.509 сертификатов.

## Требования

- Python 3.8 или выше
- Зависимости указаны в `requirements.txt`

## Установка

### 1. Клонирование репозитория


git clone <url-репозитория>
cd PythonProjectMicroPKI
2. Создание виртуального окружения

# Создание виртуального окружения
python -m venv venv

# Активация виртуального окружения:
# На Windows:
venv\Scripts\activate
# На macOS/Linux:
source venv/bin/activate
3. Установка зависимостей

pip install -r requirements.txt
4. Установка пакета в режиме разработки

pip install -e .
Использование
Создание корневого CA с RSA ключом

# Создайте файл с паролем
echo "mysecurepassphrase" > secrets/ca.pass

# Создайте корневой CA
micropki ca init \
  --subject "/CN=My Root CA/O=My Organization/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file secrets/ca.pass \
  --out-dir ./my-pki \
  --validity-days 3650 \
  --log-file ./my-pki/ca-init.log
Создание корневого CA с ECC ключом (P-384)

micropki ca init \
  --subject "CN=My ECC Root CA,O=My Organization,C=RU" \
  --key-type ecc \
  --key-size 384 \
  --passphrase-file secrets/ca.pass \
  --out-dir ./my-pki-ecc \
  --validity-days 3650
Параметры команды ca init
Параметр	Описание	Обязательный	По умолчанию
--subject	Distinguished Name (например, /CN=My Root CA/O=Demo)	Да	-
--key-type	Тип ключа (rsa или ecc)	Нет	rsa
--key-size	Размер ключа в битах (4096 для RSA, 384 для ECC)	Нет	4096
--passphrase-file	Путь к файлу с парольной фразой	Да	-
--out-dir	Выходная директория	Нет	./pki
--validity-days	Срок действия сертификата в днях	Нет	3650
--log-file	Путь к файлу лога	Нет	stderr
Структура выходной директории
После успешного выполнения команды будет создана следующая структура:

~~~~
<out-dir>/
├── private/
│   └── ca.key.pem         
├── certs/
│   └── ca.cert.pem          
└── policy.txt
~~~~
Проверка сертификата с помощью OpenSSL

# Просмотр информации о сертификате
openssl x509 -in my-pki/certs/ca.cert.pem -text -noout

# Проверка самоподписанного сертификата
openssl verify -CAfile my-pki/certs/ca.cert.pem my-pki/certs/ca.cert.pem
Тестирование
Запуск всех тестов

pytest tests/ -v
Запуск тестов с покрытием кода

pytest --cov=micropki tests/ -v
Ручное тестирование

# Создайте тестовый пароль
echo "testpass123" > test-pass.txt

# Создайте тестовый CA
micropki ca init \
  --subject "/CN=Test CA" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file test-pass.txt \
  --out-dir ./test-pki

# Проверьте созданные файлы
ls -la test-pki/
ls -la test-pki/private/
ls -la test-pki/certs/
Архитектура проекта
~~~
PythonProjectMicroPKI/
├── micropki/                  
│   ├── __init__.py            
│   ├── cli.py                
│   ├── ca.py                  
│   ├── certificates.py        
│   ├── crypto_utils.py        
│   └── logger.py              
├── tests/                      
│   ├── __init__.py
│   ├── test_ca.py             
│   └── test_crypto_utils.py   
├── requirements.txt           
├── setup.py                    
├── pyproject.toml              
└── README.md                   
# MicroPKI - Minimal Public Key Infrastructure
~~~
Минимальная реализация PKI для образовательных целей.

## Sprint 2 Features

- **Intermediate CA**: Создание промежуточного удостоверяющего центра
- **Certificate Templates**: Шаблоны для сертификатов server, client, code_signing
- **Subject Alternative Names (SAN)**: Поддержка DNS, IP, email, URI
- **Chain Validation**: Проверка цепочек сертификатов
## Требования

- Python 3.8 или выше
- Зависимости указаны в requirements.txt

## Установка

### 1. Клонирование репозитория


git clone <url-репозитория>
cd PythonProjectMicroPKI
2. Создание виртуальной среды

python -m venv venv
Активация виртуального окружения:

Windows: venv\Scripts\activate

macOS/Linux: source venv/bin/activate

3. Установка зависимостей

pip install -r requirements.txt
4. Установка пакета в режиме разработки

pip install -e .
Использование
Подготовка паролей
Создайте файлы с паролями для защиты закрытых ключей:


# Для корневого CA
echo "root_secure_passphrase_123" > secrets/root.pass

# Для промежуточного CA
echo "intermediate_secure_passphrase_456" > secrets/intermediate.pass
1. Создание корневого CA
RSA 4096 (рекомендуется для максимальной совместимости):


micropki ca init \
    --subject "CN=MicroPKI Root CA,O=MicroPKI,C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/root.pass \
    --out-dir ./pki \
    --validity-days 3650
ECC P-384 (более производительный):


micropki ca init \
    --subject "CN=MicroPKI ECC Root CA,O=MicroPKI,C=RU" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file secrets/root.pass \
    --out-dir ./pki \
    --validity-days 3650
2. Создание промежуточного CA

micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=MicroPKI Intermediate CA,O=MicroPKI,C=RU" \
    --key-type rsa \
    --passphrase-file secrets/intermediate.pass \
    --out-dir ./pki \
    --validity-days 1825 \
    --pathlen 0
3. Выпуск сертификатов
Серверный сертификат (для HTTPS/TLS)

micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com,O=MicroPKI,C=RU" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir ./pki/certs \
    --validity-days 365
Клиентский сертификат (для аутентификации)

micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith,EMAIL=alice@example.com,O=MicroPKI" \
    --san email:alice@example.com \
    --out-dir ./pki/certs \
    --validity-days 365
Сертификат для подписи кода

micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer,O=MicroPKI" \
    --out-dir ./pki/certs \
    --validity-days 365
4. Проверка цепочки сертификатов

micropki verify \
    --leaf ./pki/certs/example.com.cert.pem \
    --intermediate ./pki/certs/intermediate.cert.pem \
    --root ./pki/certs/ca.cert.pem
## Использование

### 1. Создание Root CA


micropki ca init \
    --subject "CN=MicroPKI Root CA,O=MicroPKI" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/root.pass \
    --out-dir ./pki \
    --validity-days 3650
2. Создание Intermediate CA

micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" \
    --key-type rsa \
    --passphrase-file secrets/intermediate.pass \
    --out-dir ./pki \
    --validity-days 1825 \
    --pathlen 0
3. Выпуск сертификатов
Серверный сертификат

micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com,O=MicroPKI" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir ./pki/certs \
    --validity-days 365
Клиентский сертификат

micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith,EMAIL=alice@example.com" \
    --san email:alice@example.com \
    --out-dir ./pki/certs
Сертификат для подписи кода

micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --out-dir ./pki/certs
4. Проверка цепочки сертификатов

micropki verify \
    --leaf ./pki/certs/example.com.cert.pem \
    --intermediate ./pki/certs/intermediate.cert.pem \
    --root ./pki/certs/ca.cert.pem
Структура директорий
~~~~
pki/
├── private/
│   ├── ca.key.pem               # Зашифрованный ключ Root CA
│   └── intermediate.key.pem     # Зашифрованный ключ Intermediate CA
├── certs/
│   ├── ca.cert.pem             # Сертификат Root CA
│   ├── intermediate.cert.pem   # Сертификат Intermediate CA
│   └── *.cert.pem              # Выпущенные сертификаты
├── csrs/                       # Опционально, для хранения CSR
└── policy.txt                  # Документ политики
~~~~
##Требования
Python ≥ 3.8

cryptography ≥ 41.0.0

pytest ≥ 7.0.0 (для тестирования)

Лицензия
MIT



## Установка и тестирование

# Установка зависимостей
pip install cryptography

# Запуск тестов
pytest tests/ -v

# Проверка цепочки сертификатов с OpenSSL
openssl verify -CAfile pki/certs/ca.cert.pem -untrusted pki/certs/intermediate.cert.pem pki/certs/example.com.cert.pem
# Архитектура
~~~~
PythonProjectMicroPKI/
├── micropki/
│   ├── __init__.py              # Версия 0.6.0
│   ├── __main__.py
│   ├── ca.py                    # Root CA
│   ├── certificates.py          # Работа с сертификатами
│   ├── chain.py                 # Базовая проверка цепочек
│   ├── cli.py                   # CLI интерфейс (с client subcommand)
│   ├── client_cli.py            # Клиентские команды 
│   ├── crypto_utils.py          # Криптографические утилиты
│   ├── csr.py                   # CSR генерация и обработка
│   ├── database.py              # SQLite база данных
│   ├── intermediate.py          # Intermediate CA (с поддержкой CSR)
│   ├── logger.py                # Логирование
│   ├── ocsp.py                  # OCSP responder логика
│   ├── ocsp_responder.py        # OCSP HTTP сервер
│   ├── repository.py            # HTTP репозиторий (с /request-cert)
│   ├── revocation.py            # CRL генерация
│   ├── revocation_check.py      # Проверка отзыва 
│   ├── serial.py                # Генерация серийных номеров
│   ├── templates.py             # Шаблоны сертификатов
│   └── validation.py            # Path validation engine 
├── tests/
│   ├── __init__.py
│   ├── test_ca.py
│   ├── test_crypto_utils.py
│   ├── test_csr.py
│   ├── test_database.py
│   ├── test_ocsp.py
│   ├── test_revocation.py
│   ├── test_serial.py
│   ├── test_templates.py
│   ├── test_client_cli.py
│   ├── test_validation.py
│   └── test_revocation_fallback.py
├── requirements.txt
├── setup.py
├── pyproject.toml
└── README.md
~~~~
# MicroPKI - Minimal Public Key Infrastructure

Минимальная инфраструктура открытых ключей для создания и управления удостоверяющими центрами.

## Sprint 3 Features
- **Certificate Database**: SQLite хранилище для всех выданных сертификатов
- **Unique Serial Numbers**: Гарантированно уникальные 64-битные серийные номера
- **HTTP Repository Server**: REST API для получения сертификатов
- **Certificate Management**: CLI команды для просмотра и управления сертификатами

## Быстрый старт

### 1. Инициализация базы данных

micropki db init --db-path ./pki/micropki.db
2. Создание Root CA

echo "securepass" > secrets/root.pass
micropki ca init \
    --subject "CN=My Root CA,O=Demo,C=RU" \
    --passphrase-file secrets/root.pass \
    --out-dir ./pki
3. Создание Intermediate CA

echo "intermediatepass" > secrets/intermediate.pass
micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=Intermediate CA,O=Demo" \
    --passphrase-file secrets/intermediate.pass \
    --out-dir ./pki
4. Выпуск сертификата (автоматически добавляется в БД)

micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com" \
    --san dns:example.com
5. Просмотр сертификатов

# Список всех сертификатов
micropki ca list-certs --format table

# Только валидные
micropki ca list-certs --status valid --format json

# Получить сертификат по серийному номеру
micropki ca show-cert 2A7F1234... --format pem
6. Запуск репозитория

# Запуск HTTP сервера
micropki repo serve --host 127.0.0.1 --port 8080

# Проверка статуса
micropki repo status --port 8080
7. API запросы

# Получить сертификат по серийному номеру
curl http://localhost:8080/certificate/2A7F... --output cert.pem

# Получить корневой сертификат
curl http://localhost:8080/ca/root --output root.pem

# Получить промежуточный сертификат
curl http://localhost:8080/ca/intermediate --output intermediate.pem

# CRL endpoint (заглушка)
curl http://localhost:8080/crl
# 501 Not Implemented
Команды CLI
Управление базой данных
Команда	Описание
db init --db-path PATH	Инициализация SQLite базы данных
Управление сертификатами
Команда	Описание
ca list-certs [--status STATUS] [--format FORMAT]	Список сертификатов
ca show-cert SERIAL [--format FORMAT]	Показать сертификат
ca init	Создать Root CA
ca issue-intermediate	Создать Intermediate CA
ca issue-cert	Выпустить сертификат
Репозиторий
Команда	Описание
repo serve [--host HOST] [--port PORT]	Запуск HTTP сервера
repo status [--host HOST] [--port PORT]	Проверка статуса сервера
Проверка цепочки
Команда	Описание
verify --leaf FILE --intermediate FILE --root FILE	Проверка цепочки сертификатов
Структура базы данных
sql
CREATE TABLE certificates (
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
);
API Endpoints
Метод	Endpoint	Описание
GET	/certificate/{serial}	Получить сертификат по серийному номеру
GET	/ca/root	Получить корневой сертификат
GET	/ca/intermediate	Получить промежуточный сертификат
GET	/crl	CRL (заглушка - 501)
GET	/health	Проверка здоровья сервера
Тестирование Sprint 3

# Запуск всех тестов
pytest tests/ -v

# Только тесты Sprint 3
pytest tests/test_database.py tests/test_serial.py -v

# Тестирование API (требуется запущенный сервер)
pytest tests/test_repository.py -v
Интеграционный тест

# Полный цикл работы
./demo_sprint3.sh
Лицензия
MIT



## 9. Скрипт демонстрации (demo_sprint3.sh)



set -e

echo "=== MicroPKI Sprint 3 Demo ==="

# Clean up
rm -rf ./pki ./secrets
mkdir -p secrets

# Create passphrase files
echo "rootpass123" > secrets/root.pass
echo "intermediatepass456" > secrets/intermediate.pass

# 1. Initialize database
echo -e "\n1. Initializing database..."
micropki db init --db-path ./pki/micropki.db

# 2. Create Root CA
echo -e "\n2. Creating Root CA..."
micropki ca init \
    --subject "CN=Demo Root CA,O=Demo,C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/root.pass \
    --out-dir ./pki \
    --validity-days 3650

# 3. Create Intermediate CA
echo -e "\n3. Creating Intermediate CA..."
micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=Demo Intermediate CA,O=Demo" \
    --key-type rsa \
    --passphrase-file secrets/intermediate.pass \
    --out-dir ./pki \
    --validity-days 1825

# 4. Issue server certificate
echo -e "\n4. Issuing server certificate..."
micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=demo.example.com,O=Demo" \
    --san dns:demo.example.com \
    --san dns:www.demo.example.com \
    --out-dir ./pki/certs \
    --validity-days 365

# 5. Issue client certificate
echo -e "\n5. Issuing client certificate..."
micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith,EMAIL=alice@example.com" \
    --san email:alice@example.com \
    --out-dir ./pki/certs \
    --validity-days 365

# 6. List certificates
echo -e "\n6. Listing all certificates:"
micropki ca list-certs --format table

# 7. Show certificate details
echo -e "\n7. Showing certificate details:"
SERIAL=$(micropki ca list-certs --format json | python3 -c "import sys,json; data=json.load(sys.stdin); print(data[0]['serial_hex'])" 2>/dev/null || echo "unknown")
if [ "$SERIAL" != "unknown" ]; then
    micropki ca show-cert "$SERIAL" --format text
fi

# 8. Start repository server in background
echo -e "\n8. Starting repository server..."
micropki repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db &
SERVER_PID=$!
sleep 2

# 9. Test API endpoints
echo -e "\n9. Testing API endpoints..."
curl -s http://localhost:8080/health && echo " - Health OK"
curl -s -o /tmp/root.pem http://localhost:8080/ca/root && echo " - Root CA downloaded"
curl -s -o /tmp/intermediate.pem http://localhost:8080/ca/intermediate && echo " - Intermediate CA downloaded"

if [ "$SERIAL" != "unknown" ]; then
    curl -s -o /tmp/cert.pem "http://localhost:8080/certificate/$SERIAL" && echo " - Certificate downloaded"
fi

curl -s http://localhost:8080/crl && echo " - CRL endpoint (501)"

# 10. Stop server
echo -e "\n10. Stopping server..."
kill $SERVER_PID 2>/dev/null || true

echo -e "\n=== Demo completed successfully ==="
10. Обновление setup.py
python
from setuptools import setup, find_packages

setup(
    name="micropki",
    version="0.3.0",
    description="Minimal Public Key Infrastructure for educational purposes",
    author="MicroPKI Team",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "micropki=micropki.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
## Sprint 4 Features (CRL System)
- **Certificate Revocation**: Отзыв сертификатов с указанием причины
- **CRL Generation**: Генерация CRL v2 с поддержкой всех RFC 5280 reason codes
- **CRL Distribution**: HTTP endpoints для получения CRL
- **Revocation Status Check**: Проверка статуса сертификата

### Новые команды CLI

#### Отзыв сертификата

# Отзыв с причиной
micropki ca revoke 2A7F1234... --reason keyCompromise

# Принудительный отзыв без подтверждения
micropki ca revoke 3B8E5678... --reason superseded --force

# Поддерживаемые причины отзыва:
# unspecified, keyCompromise, cACompromise, affiliationChanged,
# superseded, cessationOfOperation, certificateHold,
# removeFromCRL, privilegeWithdrawn, aACompromise
Генерация CRL

# Генерация CRL для Intermediate CA
micropki ca gen-crl --ca intermediate --next-update 14

# Генерация CRL для Root CA с указанием выходного файла
micropki ca gen-crl --ca root --out-file ./custom/root.crl.pem
Проверка статуса отзыва

# Проверка статуса сертификата
micropki ca check-revoked 2A7F1234...
CRL HTTP Endpoints

# Получить CRL Intermediate CA
curl http://localhost:8080/crl

# Получить CRL Root CA
curl http://localhost:8080/crl?ca=root

# Проверка CRL с OpenSSL
openssl crl -inform PEM -in crl.pem -text -noout
openssl crl -inform PEM -in crl.pem -CAfile ca.cert.pem -noout
Структура директорий (Sprint 4)
~~~
<out-dir>/
├── private/
│   ├── ca.key.pem
│   └── intermediate.key.pem
├── certs/
│   ├── ca.cert.pem
│   ├── intermediate.cert.pem
│   └── *.cert.pem
├── crl/                          # NEW
│   ├── root.crl.pem
│   └── intermediate.crl.pem
├── micropki.db
└── policy.txt
~~~

## Запуск тестов


# Запуск всех тестов Sprint 4
pytest tests/test_revocation.py -v

# Запуск всех тестов проекта
pytest tests/ -v
Проверка реализации
Для проверки работоспособности выполните:


chmod +x demo_sprint4.sh
./demo_sprint4.sh
# Спринт 5 
Sprint 5: OCSP Responder (НОВОЕ!)
OCSP (Online Certificate Status Protocol) позволяет проверять статус сертификата в реальном времени без скачивания CRL.

1. Выпуск сертификата для OCSP подписи

micropki ocsp issue-ocsp-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --subject "CN=OCSP Responder,O=MicroPKI" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:ocsp.example.com \
    --ocsp-url http://ocsp.example.com:8081/ocsp \
    --out-dir ./pki/certs \
    --validity-days 365
Особенности OCSP сертификата:

Basic Constraints: CA=FALSE

Key Usage: digitalSignature

Extended Key Usage: OCSPSigning (1.3.6.1.5.5.7.3.9)

Закрытый ключ хранится НЕЗАШИФРОВАННЫМ (требование OCSP responder)

2. Запуск OCSP responder

micropki ocsp serve \
    --host 127.0.0.1 \
    --port 8081 \
    --db-path ./pki/micropki.db \
    --responder-cert ./pki/certs/ocsp.cert.pem \
    --responder-key ./pki/certs/ocsp.key.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --cache-ttl 120 \
    --log-file ./logs/ocsp.log
Параметры ocsp serve:

Параметр	Описание	По умолчанию
--host	Адрес для привязки	127.0.0.1
--port	TCP порт	8081
--db-path	Путь к SQLite базе данных	./pki/micropki.db
--responder-cert	Сертификат OCSP подписанта	Обязательный
--responder-key	Закрытый ключ OCSP (unencrypted)	Обязательный
--ca-cert	Сертификат издателя (CA)	Обязательный
--cache-ttl	Время жизни кэша в секундах	60
--log-file	Файл для логов	stderr
3. Запросы к OCSP responder
С помощью OpenSSL

# Запрос статуса сертификата
openssl ocsp -issuer ./pki/certs/intermediate.cert.pem \
    -cert ./pki/certs/example.com.cert.pem \
    -url http://localhost:8081/ocsp \
    -resp_text \
    -nonce

# Запрос по серийному номеру
openssl ocsp -issuer ./pki/certs/intermediate.cert.pem \
    -serial 0x2A7F3B8E1C4D5F6A \
    -url http://localhost:8081/ocsp

# С сохранением ответа в файл
openssl ocsp -issuer ./pki/certs/intermediate.cert.pem \
    -cert ./pki/certs/example.com.cert.pem \
    -url http://localhost:8081/ocsp \
    -respout ./response.der

# Проверка подписи OCSP ответа
openssl ocsp -respin ./response.der \
    -CAfile ./pki/certs/intermediate.cert.pem \
    -verify_other ./pki/certs/ocsp.cert.pem
С помощью curl

# OCSP запрос требует бинарные данные, используйте openssl для генерации
openssl ocsp -issuer ca.pem -cert cert.pem -reqout request.der
curl -X POST http://localhost:8081/ocsp \
    -H "Content-Type: application/ocsp-request" \
    --data-binary @request.der \
    --output response.der
4. Health check

# Проверка состояния OCSP responder
curl http://localhost:8081/health
# Ответ: OK
5. Возможные статусы ответа
Статус	Описание
good	Сертификат действителен (не отозван)
revoked	Сертификат отозван (с указанием даты и причины)
unknown	Сертификат не найден или выдан другим CA
HTTP Репозиторий
Запуск сервера

# Запуск HTTP сервера для распространения сертификатов и CRL
micropki repo serve \
    --host 127.0.0.1 \
    --port 8080 \
    --db-path ./pki/micropki.db \
    --cert-dir ./pki/certs \
    --out-dir ./pki
API Endpoints
Метод	Endpoint	Описание
GET	/certificate/{serial}	Получить сертификат по серийному номеру
GET	/ca/root	Получить корневой сертификат
GET	/ca/intermediate	Получить промежуточный сертификат
GET	/crl	Получить CRL Intermediate CA
GET	/crl?ca=root	Получить CRL Root CA
GET	/health	Проверка здоровья сервера
Примеры запросов
bash
# Получить сертификат по серийному номеру
curl http://localhost:8080/certificate/2A7F3B8E1C4D5F6A --output cert.pem

# Получить корневой сертификат
curl http://localhost:8080/ca/root --output root.pem

# Получить промежуточный сертификат
curl http://localhost:8080/ca/intermediate --output intermediate.pem

# Получить CRL
curl http://localhost:8080/crl --output intermediate.crl.pem

# Получить CRL Root CA
curl "http://localhost:8080/crl?ca=root" --output root.crl.pem

# Проверка статуса сервера
curl http://localhost:8080/health
Структура директорий (Sprint 5)
~~~
<out-dir>/
├── private/                      # Зашифрованные закрытые ключи
│   ├── ca.key.pem               # Ключ корневого CA
│   └── intermediate.key.pem     # Ключ промежуточного CA
├── certs/                        # Сертификаты
│   ├── ca.cert.pem              # Сертификат корневого CA
│   ├── intermediate.cert.pem    # Сертификат промежуточного CA
│   ├── ocsp.cert.pem            # Сертификат OCSP подписанта (Sprint 5)
│   ├── ocsp.key.pem             # Ключ OCSP (НЕЗАШИФРОВАННЫЙ)
│   └── *.cert.pem               # Выпущенные сертификаты
├── crl/                          # Списки отзыва (Sprint 4)
│   ├── root.crl.pem             # CRL корневого CA
│   └── intermediate.crl.pem     # CRL промежуточного CA
├── csrs/                         # Опционально, для хранения CSR
├── micropki.db                   # База данных SQLite
└── policy.txt                    # Документ политики безопасности
Структура базы данных
~~~
-- Таблица сертификатов
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL,           -- 'valid', 'revoked', 'expired'
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);

-- Индексы для производительности
CREATE INDEX idx_serial_hex ON certificates(serial_hex);
CREATE INDEX idx_status ON certificates(status);
CREATE INDEX idx_issuer ON certificates(issuer);

-- Таблица метаданных CRL (Sprint 4)
CREATE TABLE crl_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_subject TEXT NOT NULL,
    crl_number INTEGER NOT NULL,
    last_generated TEXT NOT NULL,
    next_update TEXT NOT NULL,
    crl_path TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_ca_subject ON crl_metadata(ca_subject);
Проверка с помощью OpenSSL
Проверка сертификатов

# Просмотр информации о сертификате
openssl x509 -in pki/certs/ca.cert.pem -text -noout

# Проверка самоподписанного сертификата
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem

# Проверка цепочки сертификатов
openssl verify -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/example.com.cert.pem
Проверка CRL

# Просмотр CRL
openssl crl -inform PEM -in pki/crl/intermediate.crl.pem -text -noout

# Проверка подписи CRL
openssl crl -inform PEM -in pki/crl/intermediate.crl.pem \
    -CAfile pki/certs/intermediate.cert.pem -noout
Проверка OCSP (Sprint 5)

# Запрос статуса через OCSP
openssl ocsp -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/example.com.cert.pem \
    -url http://localhost:8081/ocsp \
    -resp_text

# Проверка OCSP ответа
openssl ocsp -respin response.der \
    -CAfile pki/certs/intermediate.cert.pem \
    -verify_other pki/certs/ocsp.cert.pem
Тестирование
Запуск всех тестов

pytest tests/ -v

## Спринт 6 

- **Client CSR Generation**: Генерация закрытых ключей и CSR для подачи в CA
- **Certificate Request API**: HTTP endpoint для автоматической выдачи сертификатов по CSR
- **Path Validation Engine**: Полная RFC 5280 валидация цепочек сертификатов
- **Revocation Checking**: Проверка статуса отзыва с OCSP-first, CRL-fallback логикой
- **Chain Building**: Автоматическое построение цепочки от листового до доверенного корневого сертификата
- **Extended Key Usage Validation**: Проверка соответствия EKU шаблону (server, client, code_signing)

## Требования

- Python 3.8 или выше
- Зависимости указаны в requirements.txt

## Установка

### 1. Клонирование репозитория


git clone <url-репозитория>
cd PythonProjectMicroPKI
2. Создание виртуального окружения
Структура директорий
~~~
pki/
├── private/                      # Зашифрованные закрытые ключи
│   ├── ca.key.pem               # Ключ корневого CA
│   └── intermediate.key.pem     # Ключ промежуточного CA
├── certs/                        # Сертификаты
│   ├── ca.cert.pem              # Сертификат корневого CA
│   ├── intermediate.cert.pem    # Сертификат промежуточного CA
│   ├── ocsp.cert.pem            # Сертификат OCSP подписанта
│   ├── ocsp.key.pem             # Ключ OCSP (НЕЗАШИФРОВАННЫЙ)
│   └── *.cert.pem               # Выпущенные сертификаты
├── crl/                          # Списки отзыва
│   ├── root.crl.pem             # CRL корневого CA
│   └── intermediate.crl.pem     # CRL промежуточного CA
├── csrs/                         # Опционально, для хранения CSR
├── micropki.db                   # База данных SQLite
└── policy.txt                    # Документ политики безопасности
~~~
Валидация цепочки сертификатов
Движок валидации реализует упрощённую версию RFC 5280 и выполняет следующие проверки:

Построение цепочки: Автоматическое построение пути от листового до доверенного корневого сертификата

Проверка подписи: Верификация подписи каждого сертификата публичным ключом издателя

Период действия: Проверка, что текущее время находится в пределах notBefore/notAfter

Basic Constraints: Проверка CA флага и ограничений пути

Key Usage: Проверка наличия необходимых key usage расширений

Extended Key Usage: Опциональная проверка соответствия EKU шаблону

Отзыв: OCSP-first, CRL-fallback проверка статуса

Пример вывода валидации

============================================================
CERTIFICATE CHAIN VALIDATION
============================================================
Leaf Subject: CN=app.example.com,O=MicroPKI
Validation Time: 2024-01-15 10:30:00
------------------------------------------------------------

[1] Certificate: CN=app.example.com,O=MicroPKI
    Issuer: CN=MicroPKI Intermediate CA,O=MicroPKI,C=RU
    Serial: 2A7F3B8E1C4D5F6A
    Status: ✓ VALID
      ✓ Signature Verification: Signature is valid
      ✓ Validity Period: Valid from 2024-01-01 to 2025-01-01
      ✓ Basic Constraints: No Basic Constraints (default CA=FALSE)
      ○ Path Length: No path length constraint
      ✓ Key Usage: Has appropriate key usage for end-entity
      ✓ Extended Key Usage: Certificate has server EKU

[2] Certificate: CN=MicroPKI Intermediate CA,O=MicroPKI,C=RU
    Issuer: CN=MicroPKI Root CA,O=MicroPKI,C=RU
    Serial: 3B8E5F2A7D1C4E6B
    Status: ✓ VALID
      ✓ Signature Verification: Signature is valid
      ✓ Validity Period: Valid from 2023-01-01 to 2028-01-01
      ✓ Basic Constraints: CA=True
      ✓ Path Length: Path length constraint: 0
      ✓ Key Usage: CA certificate has keyCertSign
      ○ Extended Key Usage: No Extended Key Usage extension

------------------------------------------------------------
Revocation Status: GOOD
------------------------------------------------------------
OVERALL RESULT: VALID ✓
============================================================
Проверка с помощью OpenSSL
Просмотр сертификата

openssl x509 -in pki/certs/ca.cert.pem -text -noout
Проверка цепочки

openssl verify -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/app.cert.pem
Проверка CRL

openssl crl -inform PEM -in pki/crl/intermediate.crl.pem -text -noout
openssl crl -inform PEM -in pki/crl/intermediate.crl.pem \
    -CAfile pki/certs/intermediate.cert.pem -noout
OCSP запрос

openssl ocsp -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/app.cert.pem \
    -url http://localhost:8081/ocsp \
    -resp_text \
    -nonce
python -m venv venv
Активация виртуального окружения:

Windows: venv\Scripts\activate

macOS/Linux: source venv/bin/activate

3. Установка зависимостей

pip install -r requirements.txt
4. Установка пакета в режиме разработки

pip install -e .
Быстрый старт (Sprint 6)
1. Подготовка паролей

mkdir -p secrets
echo "root_secure_passphrase_123" > secrets/root.pass
echo "intermediate_secure_passphrase_456" > secrets/intermediate.pass
2. Создание Root CA

micropki ca init \
    --subject "CN=MicroPKI Root CA,O=MicroPKI,C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/root.pass \
    --out-dir ./pki \
    --validity-days 3650
3. Создание Intermediate CA

micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=MicroPKI Intermediate CA,O=MicroPKI,C=RU" \
    --key-type rsa \
    --passphrase-file secrets/intermediate.pass \
    --out-dir ./pki \
    --validity-days 1825 \
    --pathlen 0
4. Инициализация базы данных

micropki db init --db-path ./pki/micropki.db
5. Генерация CSR (Клиент)

micropki client gen-csr \
    --subject "CN=app.example.com,O=MicroPKI" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:app.example.com \
    --san dns:api.example.com \
    --out-key ./app.key.pem \
    --out-csr ./app.csr.pem
6. Запрос сертификата через API

# Запуск репозитория в фоне
micropki repo serve --host 127.0.0.1 --port 8080 &
REPO_PID=$!

# Отправка CSR и получение сертификата
micropki client request-cert \
    --csr ./app.csr.pem \
    --template server \
    --ca-url http://localhost:8080 \
    --out-cert ./app.cert.pem

# Остановка репозитория
kill $REPO_PID
7. Валидация цепочки сертификатов

micropki client validate \
    --cert ./app.cert.pem \
    --untrusted ./pki/certs/intermediate.cert.pem \
    --trusted ./pki/certs/ca.cert.pem \
    --mode full \
    --format text
8. Проверка статуса отзыва

# Отзыв сертификата
micropki ca revoke <SERIAL> --reason keyCompromise --force
# MicroPKI - Минимальная Public Key Infrastructure

##  Спринт 7  - Усиление безопасности

MicroPKI — это легковесная реализация PKI для образовательных и тестовых целей. Sprint 7 добавляет систему аудита с криптографической целостностью, контроль политик безопасности, rate limiting, Certificate Transparency лог и механизм обнаружения скомпрометированных ключей.


## Новые возможности Спринта 7

### 1. Аудит с криптографической целостностью
- Все операции логируются в формате NDJSON с SHA-256 hash-цепочкой
- Невозможно подделать или удалить записи без обнаружения
- Команды для просмотра и верификации логов

### 2. Контроль политик безопасности
- Проверка минимальных размеров ключей (RSA 2048/3072/4096, ECC P-256/P-384)
- Ограничение максимального срока действия сертификатов
- Валидация типов SAN в зависимости от шаблона
- Запрет wildcard-сертификатов (настраивается)

### 3. Rate Limiting
- Ограничение количества запросов на клиента для HTTP серверов
- Защита от DoS-атак на репозиторий и OCSP responder

### 4. Certificate Transparency (CT) лог
- Симуляция CT лога для отслеживания выданных сертификатов
- Возможность проверки наличия сертификата в логе

### 5. Обнаружение компрометации ключей
- Маркировка скомпрометированных ключей
- Блокировка выдачи новых сертификатов по скомпрометированным ключам



## Система аудита и целостность логов

### Формат аудит лога

Аудит лог хранится в `./pki/audit/audit.log` в формате NDJSON с hash-цепочкой:

{
  "timestamp": "2026-02-13T15:04:05.123456Z",
  "level": "AUDIT",
  "operation": "issue_certificate",
  "status": "success",
  "message": "Issued server certificate for CN=example.com",
  "metadata": {
    "serial": "2A7F8B3C...",
    "subject": "CN=example.com,O=MicroPKI",
    "template": "server",
    "requester": "127.0.0.1"
  },
  "integrity": {
    "prev_hash": "abc123...",
    "hash": "def456..."
  }
}
Команды для работы с аудит логом
Просмотр аудит логов

# Показать все AUDIT события за последние 24 часа
micropki audit query --from "$(date -d 'yesterday' -Iseconds)" --level AUDIT --format table

# Показать события выдачи сертификатов в формате JSON
micropki audit query --operation issue_certificate --format json

# Поиск по серийному номеру
micropki audit query --serial "2A7F8B3C" --format csv

# Фильтр по временному диапазону
micropki audit query --from "2026-01-01T00:00:00" --to "2026-12-31T23:59:59"
Проверка целостности аудит лога

# Проверка целостности всего лога
micropki audit verify

# Проверка с указанием путей
micropki audit verify --log-file ./pki/audit/audit.log --chain-file ./pki/audit/chain.dat
При успешной проверке:


 Audit log integrity verified
При обнаружении подделки:


 Audit log integrity check FAILED!
  Line 42: Hash chain broken. Expected prev_hash=abc..., got def...
  Line 43: Hash mismatch. Entry may be tampered.
Контроль политик безопасности
Применяемые политики
Тип	Параметр	Минимум	Максимум
RSA	Root CA	4096 бит	-
Intermediate CA	3072 бит	-
End-entity	2048 бит	-
ECC	Root/Intermediate	P-384	P-384
End-entity	P-256	P-384
Validity	Root CA	-	3650 дней (10 лет)
Intermediate CA	-	1825 дней (5 лет)
End-entity	-	365 дней (1 год)
SAN ограничения по шаблонам
Шаблон	Разрешённые SAN типы
server	dns, ip
client	dns, email
code_signing	dns, uri
Примеры нарушения политик

# Попытка выпустить сертификат с RSA-1024 (будет отклонено)
micropki ca issue-cert --ca-cert ca.cert.pem --ca-key ca.key.pem \
    --template server --subject "/CN=test" --key-type rsa --key-size 1024
# Ошибка: RSA key size must be at least 2048 bits for end_entity

# Попытка выпустить сертификат с wildcard (по умолчанию запрещено)
micropki ca issue-cert --san dns:*.example.com ...
# Ошибка: Wildcard DNS name '*.example.com' is not allowed by policy

# Попытка выпустить code_signing с email SAN
micropki ca issue-cert --template code_signing --san email:test@example.com ...
# Ошибка: SAN type 'email' not allowed for code_signing

# Попытка выпустить сертификат на 2 года (превышает лимит)
micropki ca issue-cert --validity-days 730 ...
# Ошибка: Validity period 730 days exceeds maximum 365 days for end_entity
Настройка политик через конфигурационный файл
Создайте micropki.yaml:


policy:
  # Разрешить wildcard сертификаты (по умолчанию false)
  allow_wildcards: false
  
  # Максимальный срок действия для разных типов (в днях)
  max_validity:
    root: 3650      # 10 лет
    intermediate: 1825  # 5 лет
    end_entity: 365     # 1 год
  
  # Минимальные размеры ключей
  min_key_size:
    rsa:
      root: 4096
      intermediate: 3072
      end_entity: 2048
    ecc:
      root: 384
      intermediate: 384
      end_entity: 256
Certificate Transparency (CT) лог
Что это?
Симуляция Certificate Transparency лога — текстовый файл, в который записываются все выпущенные сертификаты.

Просмотр CT лога

# Просмотр всех записей
cat ./pki/audit/ct.log

# Формат записи:
# 2026-02-13T15:04:05.123456Z | 2A7F8B3C... | CN=example.com | AA:BB:CC:...
Проверка наличия сертификата

# Проверить, что сертификат с серийным номером залогирован
micropki audit ct-verify --serial 2A7F8B3C
#  Certificate 2A7F8B3C found in CT log

# Если не найден
micropki audit ct-verify --serial NONEXISTENT
#  Certificate NONEXISTENT not found in CT log
Интеграция с issuance
Каждый выпущенный сертификат автоматически добавляется в CT лог.

Rate Limiting
Включение rate limiting для репозитория

# Ограничение 5 запросов в секунду на клиента
micropki repo serve --rate-limit 5 --rate-burst 10

# Без rate limiting (по умолчанию)
micropki repo serve
Включение rate limiting для OCSP responder

# Ограничение 10 запросов в секунду на клиента
micropki ocsp serve --responder-cert ./ocsp.cert.pem \
    --responder-key ./ocsp.key.pem \
    --ca-cert ./ca.cert.pem \
    --rate-limit 10 --rate-burst 20
Что происходит при превышении лимита?
http
HTTP/1.1 429 Too Many Requests
Retry-After: 5
Content-Type: text/plain

Rate limit exceeded. Please try again later.
Алгоритм работы
Используется алгоритм Token Bucket

Для каждого клиента (по IP) создаётся отдельная bucket

Токены пополняются с заданной скоростью (--rate-limit токенов/сек)

Максимальное количество накопленных токенов — --rate-burst

Обнаружение компрометации ключей
Симуляция компрометации

# Отметить сертификат как скомпрометированный и отозвать его
micropki ca compromise --cert ./certs/example.com.cert.pem

# С указанием причины
micropki ca compromise --cert ./certs/example.com.cert.pem \
    --reason keyCompromise --force

# Доступные причины:
# - keyCompromise (по умолчанию)
# - cACompromise
# - affiliationChanged
# - superseded
# - cessationOfOperation
# - certificateHold
# - privilegeWithdrawn
# - aACompromise
Что происходит при компрометации?
Сертификат отзывается (status = 'revoked')

Публичный ключ добавляется в таблицу compromised_keys

Немедленно генерируется новый CRL

Создаётся AUDIT запись о компрометации

https://docs/compromise-flow.png

Блокировка выдачи по скомпрометированным ключам

# После компрометации ключа, попытка выпустить новый сертификат
# с тем же публичным ключом будет отклонена

micropki ca issue-cert --csr compromised.csr.pem --template server ...
# Ошибка: This public key has been marked as compromised. Issuance blocked.
Просмотр скомпрометированных ключей

# Прямой запрос к SQLite
sqlite3 ./pki/micropki.db "SELECT * FROM compromised_keys;"
Установка и зависимости
Требования
Python 3.8 или выше

OpenSSL (для верификации через командную строку, опционально)

Установка из исходников

# Клонирование репозитория
git clone https://github.com/your-username/micropki.git
cd micropki

# Установка зависимостей
pip install -r requirements.txt

# Установка MicroPKI
pip install -e .
Зависимости

cryptography>=41.0.0   # Криптографические операции
PyYAML>=6.0            # Поддержка конфигурационных файлов
requests>=2.31.0       # HTTP клиент для API
pytest>=7.4.0          # Тестирование
Проверка установки

micropki --version
# MicroPKI 0.7.0

# Проверка статуса (OCSP first, CRL fallback)
micropki client check-status \
    --cert ./app.cert.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem
    Тестирование
## Запуск всех тестов

pytest tests/ -v

##  Архитектура системы (Sprint 8)
~~~
┌─────────────────────────────────────────────────────────────────────────────┐
│ CLI (micropki) │
│ ca | client | repo | ocsp | audit | verify │
└───────────────────────┬─────────────────────────────────────────────────────┘
│
┌───────────────┼───────────────────────────────┐
│ │ │
┌───────▼───────┐ ┌──────▼──────┐ ┌─────────────────────▼─────────────────────┐
│ Root CA │ │ Client CLI │ │ HTTP Servers │
│ - RSA 4096 │ │ - gen-csr │ │ ┌──────────────┐ ┌──────────────────┐ │
│ - ECC P-384 │ │ - request │ │ │ Repository │ │ OCSP Responder │ │
└───────┬───────┘ │ - validate │ │ │ Port 8080 │ │ Port 8081 │ │
│ └─────────────┘ │ │ - /certificate│ │ - POST /ocsp │ │
┌───────▼───────────────────────┐ │ │ - /crl │ │ - /health │ │
│ Intermediate CA │ │ │ - /request-cert│ │ - Rate Limiting │ │
│ - Signed by Root │ │ └──────────────┘ └──────────────────┘ │
│ - Issues end-entity certs │ └─────────────────────────────────────────────┘
└───────┬───────────────────────┘
│
┌───────▼─────────────────────────────────────────────────────────────────────┐
│ Security & Persistence Layer │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
│ │ SQLite │ │ Audit │ │ Policy │ │ CT │ │ Compromised │ │
│ │ Database │ │ Log │ │ Engine │ │ Log │ │ Keys │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
~~~


##  Security Considerations 

 **MicroPKI создана для ОБУЧЕНИЯ и ПРОТОТИПИРОВАНИЯ. НЕ ИСПОЛЬЗУЙТЕ В PRODUCTION!**

### Известные ограничения безопасности
~~~
| Проблема | Риск | Рекомендация |
|----------|------|---------------|
| **End-entity ключи хранятся незашифрованными** | Компрометация ключа при доступе к файловой системе | Используйте HSM или шифрование диска |
| **Passphrase'ы читаются из файлов** | Passphrase может быть скомпрометирован | Храните passphrase'ы в защищённом хранилище (Vault, KMS) |
| **OCSP responder без HTTPS** | Возможен MITM-атака на OCSP ответы | Добавьте TLS или используйте stapling |
| **Rate limiting базовый (token bucket)** | Не защищает от DDoS с разных IP | Добавьте распределённый rate limiting (Redis) |
| **Аудит-лог подписан hash-цепочкой, но не цифровой подписью** | При компрометации системы злоумышленник может пересчитать хэши | Добавьте отдельный ключ для подписи логов |
| **Certificate Transparency симулированный** | Нет публичной верификации | Интегрируйтесь с реальными CT логами (Google, Cloudflare) |
| **SQLite без шифрования** | Все сертификаты в открытом виде | Используйте SQLCipher или PostgreSQL с TLS |
~~~
### Рекомендации для production-ready PKI

1. **Хранение ключей**: Используйте HSM (YubiHSM, AWS CloudHSM) через PKCS#11
2. **База данных**: PostgreSQL с шифрованием at-rest и TLS для подключений
3. **Аудит**: Подписывайте логи отдельным ключом, хранящимся в HSM
4. **OCSP**: Добавьте TLS и implement stapling на web-серверах
5. **Мониторинг**: Добавьте метрики (Prometheus) для всех операций
6. **HA**: Запускайте несколько экземпляров за балансировщиком

##  Тестирование (Sprint 8)

### Установка тестовых зависимостей


pip install pytest pytest-cov pytest-benchmark
Запуск всех тестов

# Все тесты с покрытием
pytest tests/ -v --cov=micropki --cov-report=term --cov-report=html

# Только unit-тесты (быстрые)
pytest tests/ -m "not perf and not slow" -v

# Performance тесты (1000 сертификатов)
pytest tests/test_performance.py -m perf -v

# С сохранением отчёта
pytest tests/ --cov=micropki --cov-report=html
open htmlcov/index.html

Performance тесты

# Запуск performance теста (1000 сертификатов)
pytest tests/test_performance.py::test_issue_1000_certificates_performance -m perf -v -s

# Ожидаемый вывод:
# ============================================================
# PERFORMANCE TEST RESULTS
# ============================================================
# Certificates issued: 1000
# Issuance time: 12.34 seconds
# Rate: 81.0 certificates/second
# Validation time: 5.67 seconds
# Rate: 176.3 validations/second
# ============================================================
Полная демонстрация (Sprint 8)
Запуск demo скрипта

# Делаем скрипт исполняемым
chmod +x demo/demo.sh

# Запускаем демонстрацию
./demo/demo.sh
Что демонстрирует скрипт
Шаг	Демонстрация	Ожидаемый результат
1-5	Создание Root и Intermediate CA	 Сертификаты созданы
6-9	Генерация CSR и выпуск сертификатов	 Сертификаты выданы
10-11	TLS сервер с HTTPS	 curl успешно подключается
12	Code signing подпись и верификация	 Подпись verified
13	Отзыв сертификата	 CRL обновлён
14	Повторное подключение с отозванным сертификатом	 Соединение отклонено
15	Проверка целостности аудит-лога	 Hash chain valid
16	Проверка политик безопасности	 Запрос отклонён
Ожидаемый вывод демо
bash
╔══════════════════════════════════════════════════════════════╗
║           MicroPKI - Демонстрация всех возможностей          ║
║                      Sprint 8 Final Demo                      ║
╚══════════════════════════════════════════════════════════════╝

[1/18] Подготовка окружения...
     Готово
[2/18] Создание passphrase файлов...
     Passphrase файлы созданы
...
[14/18] TLS Демонстрация с HTTPS сервером...
     Тестируем HTTPS соединение (должно быть успешным):
Hello from MicroPKI Secure Server!
     HTTPS соединение успешно установлено!
...
[16/18] Отзыв сертификата и тест CRL...
     Пытаемся подключиться с отозванным сертификатом:
     Соединение ОТКЛОНЕНО (сертификат отозван) - правильно!
...
╔══════════════════════════════════════════════════════════════╗
║                     ДЕМО УСПЕШНО ЗАВЕРШЕНО!                  ║
╚══════════════════════════════════════════════════════════════╝
 Полный справочник CLI команд
Управление сертификатами

# Root CA
micropki ca init --subject "/CN=Root CA" --passphrase-file root.pass

# Intermediate CA  
micropki ca issue-intermediate --root-cert ca.cert.pem --root-key ca.key.pem

# Выпуск сертификата
micropki ca issue-cert --ca-cert inter.cert.pem --template server --subject "/CN=test"

# Отзыв
micropki ca revoke <SERIAL> --reason keyCompromise --force

# Генерация CRL
micropki ca gen-crl --ca intermediate --next-update 7
Клиентские команды

# Генерация CSR
micropki client gen-csr --subject "/CN=client" --san dns:client.local

# Запрос сертификата через API
micropki client request-cert --csr request.csr --template server --ca-url http://localhost:8080

# Валидация цепочки
micropki client validate --cert cert.pem --trusted ca.cert.pem

# Проверка статуса
micropki client check-status --cert cert.pem --ca-cert ca.cert.pem
Серверы

# Repository server
micropki repo serve --port 8080 --rate-limit 10

# OCSP responder
micropki ocsp serve --responder-cert ocsp.cert.pem --responder-key ocsp.key.pem --port 8081
Аудит и безопасность

# Просмотр аудит-лога
micropki audit query --operation issue_certificate --format table

# Проверка целостности
micropki audit verify

# Проверка CT лога
micropki audit ct-verify --serial 2A7F3B8C...

# Компрометация ключа
micropki ca compromise --cert compromised.cert.pem --reason keyCompromise
🔧 Устранение неполадок
Проблема: "ModuleNotFoundError: No module named 'micropki'"

# Решение: установить пакет в режиме разработки
pip install -e .
Проблема: "Permission denied" при запуске demo.sh

# Решение: добавить права на выполнение
chmod +x demo/demo.sh
Проблема: "Address already in use" при запуске серверов

# Найти и убить процесс на порту 8080
lsof -i :8080
kill -9 <PID>
Проблема: Тесты не проходят из-за OpenSSL

# Установить OpenSSL (Ubuntu/Debian)
sudo apt-get install openssl





### Шаг 2: Создай недостающий файл `demo/demo.sh`

Я уже дал тебе полный скрипт ранее. Скопируй его в файл `demo/demo.sh` и сделай исполняемым.

### Шаг 3: Создай файл `tests/test_performance.py`

Я дал его в предыдущем сообщении. Скопируй его в папку `tests/`.

### Шаг 4: Создай файл `.github/workflows/ci.yml`

Я дал его ранее. Скопируй в папку `.github/workflows/`.

### Шаг 5: Запусти финальную проверку

Выполни эти команды в своём терминале:


# 1. Проверь, что все тесты проходят
pytest tests/ -v --cov=micropki

# 2. Запусти демо
chmod +x demo/demo.sh
./demo/demo.sh
