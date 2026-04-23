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
│   ├── __init__.py
│   ├── __main__.py
│   ├── ca.py              # Root CA
│   ├── certificates.py    # Работа с сертификатами
│   ├── chain.py           # Проверка цепочек
│   ├── cli.py             # CLI интерфейс
│   ├── crypto_utils.py    # Криптографические утилиты
│   ├── csr.py             # CSR обработка
│   ├── intermediate.py    # Intermediate CA
│   ├── logger.py          # Логирование
│   └── templates.py       # Шаблоны сертификатов
├── tests/
│   ├── __init__.py
│   ├── test_ca.py
│   ├── test_crypto_utils.py
│   ├── test_csr.py
│   ├── test_templates.py
│   └── test_chain.py
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
bash
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
bash
# Запуск всех тестов
pytest tests/ -v

# Только тесты Sprint 3
pytest tests/test_database.py tests/test_serial.py -v

# Тестирование API (требуется запущенный сервер)
pytest tests/test_repository.py -v
Интеграционный тест
bash
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
bash
# Генерация CRL для Intermediate CA
micropki ca gen-crl --ca intermediate --next-update 14

# Генерация CRL для Root CA с указанием выходного файла
micropki ca gen-crl --ca root --out-file ./custom/root.crl.pem
Проверка статуса отзыва
bash
# Проверка статуса сертификата
micropki ca check-revoked 2A7F1234...
CRL HTTP Endpoints
bash
# Получить CRL Intermediate CA
curl http://localhost:8080/crl

# Получить CRL Root CA
curl http://localhost:8080/crl?ca=root

# Проверка CRL с OpenSSL
openssl crl -inform PEM -in crl.pem -text -noout
openssl crl -inform PEM -in crl.pem -CAfile ca.cert.pem -noout
Структура директорий (Sprint 4)
text
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
text

## Запуск тестов


# Запуск всех тестов Sprint 4
pytest tests/test_revocation.py -v

# Запуск всех тестов проекта
pytest tests/ -v
Проверка реализации
Для проверки работоспособности выполните:


chmod +x demo_sprint4.sh
./demo_sprint4.sh
