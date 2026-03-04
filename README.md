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


<out-dir>/
├── private/
│   └── ca.key.pem         
├── certs/
│   └── ca.cert.pem          
└── policy.txt              
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
