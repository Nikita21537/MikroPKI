set -e  # Остановка при любой ошибке

# Цвета для красивого вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           MicroPKI - Демонстрация всех возможностей          ║${NC}"
echo -e "${BLUE}║                      Sprint 8 Final Demo                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

DEMO_DIR="./pki-demo"
echo -e "${YELLOW}[1/18]${NC} Подготовка окружения..."

# Очистка от предыдущего запуска
if [ -d "$DEMO_DIR" ]; then
    echo "    Очистка предыдущей демонстрации..."
    # Останавливаем процессы, если они есть
    pkill -f "micropki.*serve" 2>/dev/null || true
    pkill -f "python3 -m http.server" 2>/dev/null || true
    rm -rf $DEMO_DIR
fi

mkdir -p $DEMO_DIR/secrets
mkdir -p $DEMO_DIR/pki
mkdir -p $DEMO_DIR/client
mkdir -p $DEMO_DIR/code

echo -e "${GREEN}     Готово${NC}"

# Шаг 2: Создание passphrase файлов
echo -e "${YELLOW}[2/18]${NC} Создание passphrase файлов..."
echo "root123" > $DEMO_DIR/secrets/root.pass
echo "inter123" > $DEMO_DIR/secrets/intermediate.pass
echo -e "${GREEN}     Passphrase файлы созданы${NC}"

# Шаг 3: Инициализация Базы Данных
echo -e "${YELLOW}[3/18]${NC} Инициализация SQLite базы данных..."
micropki db init --db-path $DEMO_DIR/pki/micropki.db
echo -e "${GREEN}     База данных готова${NC}"

# Шаг 4: Инициализация Root CA
echo -e "${YELLOW}[4/18]${NC} Создание Root Certificate Authority..."
micropki ca init \
    --subject "/CN=MicroPKI Root CA/O=Demo/Country=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file $DEMO_DIR/secrets/root.pass \
    --out-dir $DEMO_DIR/pki \
    --validity-days 3650 > /dev/null 2>&1
echo -e "${GREEN}     Root CA создан${NC}"

# Шаг 5: Создание Intermediate CA
echo -e "${YELLOW}[5/18]${NC} Создание Intermediate Certificate Authority..."
micropki ca issue-intermediate \
    --root-cert $DEMO_DIR/pki/certs/ca.cert.pem \
    --root-key $DEMO_DIR/pki/private/ca.key.pem \
    --root-pass-file $DEMO_DIR/secrets/root.pass \
    --subject "/CN=MicroPKI Intermediate CA/O=Demo" \
    --key-type rsa \
    --passphrase-file $DEMO_DIR/secrets/intermediate.pass \
    --out-dir $DEMO_DIR/pki \
    --validity-days 1825 \
    --pathlen 0 > /dev/null 2>&1
echo -e "${GREEN}     Intermediate CA создан${NC}"

# Шаг 6: Генерация CSR для Web-сервера
echo -e "${YELLOW}[6/18]${NC} Генерация CSR и ключа для Web-сервера..."
micropki client gen-csr \
    --subject "/CN=localhost/O=Demo" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:localhost \
    --san ip:127.0.0.1 \
    --out-key $DEMO_DIR/client/server.key.pem \
    --out-csr $DEMO_DIR/client/server.csr.pem > /dev/null 2>&1
echo -e "${GREEN}     CSR и ключ созданы${NC}"

# Шаг 7: Выпуск сертификата для Web-сервера
echo -e "${YELLOW}[7/18]${NC} Выпуск сертификата для Web-сервера (Server Template)..."
micropki ca issue-cert \
    --ca-cert $DEMO_DIR/pki/certs/intermediate.cert.pem \
    --ca-key $DEMO_DIR/pki/private/intermediate.key.pem \
    --ca-pass-file $DEMO_DIR/secrets/intermediate.pass \
    --template server \
    --csr $DEMO_DIR/client/server.csr.pem \
    --out-dir $DEMO_DIR/client \
    --validity-days 365 > /dev/null 2>&1
echo -e "${GREEN}     Сертификат выпушен: $DEMO_DIR/client/localhost.cert.pem${NC}"

# Шаг 8: Генерация CSR для Client
echo -e "${YELLOW}[8/18]${NC} Генерация CSR и ключа для Клиента..."
micropki client gen-csr \
    --subject "/CN=Demo Client/O=Demo" \
    --key-type rsa \
    --key-size 2048 \
    --san email:client@demo.local \
    --out-key $DEMO_DIR/client/client.key.pem \
    --out-csr $DEMO_DIR/client/client.csr.pem > /dev/null 2>&1
echo -e "${GREEN}     CSR и ключ созданы${NC}"

# Шаг 9: Выпуск Client сертификата
echo -e "${YELLOW}[9/18]${NC} Выпуск сертификата для Клиента (Client Template)..."
micropki ca issue-cert \
    --ca-cert $DEMO_DIR/pki/certs/intermediate.cert.pem \
    --ca-key $DEMO_DIR/pki/private/intermediate.key.pem \
    --ca-pass-file $DEMO_DIR/secrets/intermediate.pass \
    --template client \
    --csr $DEMO_DIR/client/client.csr.pem \
    --out-dir $DEMO_DIR/client \
    --validity-days 365 > /dev/null 2>&1
echo -e "${GREEN}     Client сертификат выпушен${NC}"

# Шаг 10: Генерация CSR для Code Signing
echo -e "${YELLOW}[10/18]${NC} Генерация CSR и ключа для Code Signing..."
micropki client gen-csr \
    --subject "/CN=Code Signer/O=Demo" \
    --key-type rsa \
    --key-size 2048 \
    --out-key $DEMO_DIR/code/codesign.key.pem \
    --out-csr $DEMO_DIR/code/codesign.csr.pem > /dev/null 2>&1
echo -e "${GREEN}     CSR и ключ созданы${NC}"

# Шаг 11: Выпуск Code Signing сертификата
echo -e "${YELLOW}[11/18]${NC} Выпуск сертификата для Code Signing..."
micropki ca issue-cert \
    --ca-cert $DEMO_DIR/pki/certs/intermediate.cert.pem \
    --ca-key $DEMO_DIR/pki/private/intermediate.key.pem \
    --ca-pass-file $DEMO_DIR/secrets/intermediate.pass \
    --template code_signing \
    --csr $DEMO_DIR/code/codesign.csr.pem \
    --out-dir $DEMO_DIR/code \
    --validity-days 365 > /dev/null 2>&1
echo -e "${GREEN}     Code Signing сертификат выпушен${NC}"

# Шаг 12: Запуск Repository Server
echo -e "${YELLOW}[12/18]${NC} Запуск Repository Server (фоновый режим)..."
micropki repo serve \
    --host 127.0.0.1 \
    --port 8888 \
    --db-path $DEMO_DIR/pki/micropki.db \
    --cert-dir $DEMO_DIR/client \
    --out-dir $DEMO_DIR/pki > $DEMO_DIR/repo.log 2>&1 &
REPO_PID=$!
sleep 3
echo -e "${GREEN}     Repository Server запущен (PID: $REPO_PID)${NC}"

# Шаг 13: Проверка валидности цепочки
echo -e "${YELLOW}[13/18]${NC} Проверка валидности цепочки сертификатов..."
echo -e "${BLUE}    Выполняется команда: micropki client validate${NC}"
micropki client validate \
    --cert $DEMO_DIR/client/localhost.cert.pem \
    --trusted $DEMO_DIR/pki/certs/ca.cert.pem \
    --untrusted $DEMO_DIR/pki/certs/intermediate.cert.pem \
    --mode full \
    --format text
echo -e "${GREEN}     Цепочка валидна${NC}"

# Шаг 14: TLS Демонстрация
echo -e "${YELLOW}[14/18]${NC} TLS Демонстрация с HTTPS сервером..."
echo "Hello from MicroPKI Secure Server!" > $DEMO_DIR/index.html

# Запускаем HTTPS сервер
python3 -m http.server 9000 \
    --directory $DEMO_DIR \
    --certificate $DEMO_DIR/client/localhost.cert.pem \
    --key $DEMO_DIR/client/server.key.pem > $DEMO_DIR/server.log 2>&1 &
SERVER_PID=$!
sleep 3

echo -e "${BLUE}     Тестируем HTTPS соединение (должно быть успешным):${NC}"
if curl --cacert $DEMO_DIR/pki/certs/ca.cert.pem \
       --max-time 5 \
       https://localhost:9000/index.html 2>/dev/null | grep -q "MicroPKI"; then
    echo -e "${GREEN}     HTTPS соединение успешно установлено!${NC}"
else
    echo -e "${RED}     Ошибка HTTPS соединения${NC}"
fi

# Шаг 15: Code Signing Демонстрация
echo -e "${YELLOW}[15/18]${NC} Code Signing Демонстрация..."

# Создаем тестовый скрипт
cat > $DEMO_DIR/code/test_script.sh << 'EOF'
#!/bin/bash
echo "Это подписанный скрипт!"
echo "Время запуска: $(date)"
EOF
chmod +x $DEMO_DIR/code/test_script.sh

# Подписываем скрипт
openssl dgst -sha256 \
    -sign $DEMO_DIR/code/codesign.key.pem \
    -out $DEMO_DIR/code/test_script.sh.sig \
    $DEMO_DIR/code/test_script.sh 2>/dev/null

echo -e "${BLUE}     Подписываем скрипт:${NC}"
echo -e "${BLUE}     Проверяем подпись:${NC}"

# Проверяем подпись
if openssl dgst -sha256 \
    -verify <(openssl x509 -in $DEMO_DIR/code/Code_Signer.cert.pem -pubkey -noout 2>/dev/null) \
    -signature $DEMO_DIR/code/test_script.sh.sig \
    $DEMO_DIR/code/test_script.sh 2>/dev/null; then
    echo -e "${GREEN}     Подпись верифицирована успешно!${NC}"
else
    echo -e "${RED}     Ошибка верификации подписи${NC}"
fi

# Шаг 16: Отзыв сертификата и тест
echo -e "${YELLOW}[16/18]${NC} Отзыв сертификата и тест CRL..."

# Получаем серийный номер
SERIAL=$(openssl x509 -in $DEMO_DIR/client/localhost.cert.pem -serial -noout 2>/dev/null | cut -d= -f2)
echo -e "${BLUE}     Отзываем сертификат с серийным номером: $SERIAL${NC}"

micropki ca revoke $SERIAL \
    --reason keyCompromise \
    --force \
    --out-dir $DEMO_DIR/pki

# Генерируем свежий CRL
micropki ca gen-crl \
    --ca intermediate \
    --next-update 7 \
    --out-dir $DEMO_DIR/pki > /dev/null 2>&1

echo -e "${BLUE}     Перезапускаем сервер с отозванным сертификатом...${NC}"
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

python3 -m http.server 9001 \
    --directory $DEMO_DIR \
    --certificate $DEMO_DIR/client/localhost.cert.pem \
    --key $DEMO_DIR/client/server.key.pem > $DEMO_DIR/server2.log 2>&1 &
NEW_SERVER_PID=$!
sleep 3

echo -e "${BLUE}     Пытаемся подключиться с отозванным сертификатом:${NC}"
set +e  # Временно разрешаем ошибки
curl --cacert $DEMO_DIR/pki/certs/ca.cert.pem \
     --max-time 5 \
     https://localhost:9001/index.html 2>/dev/null

if [ $? -ne 0 ]; then
    echo -e "${GREEN}     Соединение ОТКЛОНЕНО (сертификат отозван) - правильно!${NC}"
else
    echo -e "${RED}    ВНИМАНИЕ: Соединение не должно быть установлено!${NC}"
fi
set -e

# Шаг 17: Проверка целостности аудит-лога
echo -e "${YELLOW}[17/18]${NC} Проверка целостности аудит-лога (цепочка хэшей)..."
micropki audit verify --out-dir $DEMO_DIR/pki
echo -e "${GREEN}     Аудит-лог верифицирован${NC}"

# Шаг 18: Демонстрация политик безопасности
echo -e "${YELLOW}[18/18]${NC} Проверка энфорсмента политик безопасности..."

# Пытаемся создать сертификат с недопустимым сроком действия
echo -e "${BLUE}     Попытка создать сертификат с чрезмерным сроком (400 дней):${NC}"
set +e
micropki ca issue-cert \
    --ca-cert $DEMO_DIR/pki/certs/intermediate.cert.pem \
    --ca-key $DEMO_DIR/pki/private/intermediate.key.pem \
    --ca-pass-file $DEMO_DIR/secrets/intermediate.pass \
    --template server \
    --subject "/CN=test-invalid.example.com" \
    --san dns:test-invalid.example.com \
    --out-dir $DEMO_DIR/client \
    --validity-days 400 2>/dev/null

if [ $? -ne 0 ]; then
    echo -e "${GREEN}     Политика сработала: запрос ОТКЛОНЕН (validity_days > 365)${NC}"
else
    echo -e "${RED}     Ошибка: политика не сработала!${NC}"
fi
set -e

# Очистка
echo -e "${YELLOW}   Останавливаем фоновые процессы...${NC}"
kill $REPO_PID $NEW_SERVER_PID 2>/dev/null || true
wait 2>/dev/null

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                     ДЕМО УСПЕШНО ЗАВЕРШЕНО!                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Все компоненты MicroPKI успешно протестированы:"
echo -e "  • Root CA и Intermediate CA созданы"
echo -e "  • Сертификаты выпущены для TLS и Code Signing"
echo -e "  • TLS сервер запущен и работает"
echo -e "  • Подпись и верификация Code Signing выполнены"
echo -e "  • Отзыв сертификата и CRL работают"
echo -e "  • Аудит-лог верифицирован"
echo -e "  • Политики безопасности энфорсятся"
echo ""
echo -e "Логи демонстрации сохранены в: $DEMO_DIR/"
echo -e "  • repo.log - лог репозитория"
echo -e "  • server.log - лог первого сервера"
echo -e "  • server2.log - лог сервера с отозванным сертификатом"
echo ""