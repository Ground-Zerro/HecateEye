#!/bin/bash
set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Конфигурационные параметры
VPN_IFACE="tun0"
VPN_GATEWAY="10.10.10.1"
VPN_NETWORK="10.10.10.0/24"
MAIN_IFACE="eth0"
MAIN_NETWORK="5.35.102.0/24"
TABLE_ID=200
TABLE_NAME="ppp-vpn"

# Функция проверки ошибок
check_error() {
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ОШИБКА]${NC} $1"
        exit 1
    else
        echo -e "${GREEN}[OK]${NC} $2"
    fi
}

# 0. Создаем необходимые директории
echo -e "${YELLOW}[0] Проверяем/создаем директории...${NC}"
mkdir -p /etc/network/if-up.d
mkdir -p /etc/network/if-down.d
check_error "Не удалось создать директории." "Директории проверены/созданы."

# 1. Создаем конфигурационный файл
echo -e "${YELLOW}[1] Создаем /etc/network/vpn-routing.conf...${NC}"
cat > /etc/network/vpn-routing.conf <<EOF
# Настройки таблицы маршрутизации
TABLE_ID=$TABLE_ID
TABLE_NAME="$TABLE_NAME"

# Интерфейс VPN
VPN_IFACE="$VPN_IFACE"
VPN_GATEWAY="$VPN_GATEWAY"
VPN_NETWORK="$VPN_NETWORK"

# Основной интерфейс
MAIN_IFACE="$MAIN_IFACE"
MAIN_NETWORK="$MAIN_NETWORK"
EOF
check_error "Не удалось создать конфигурационный файл." "Конфигурационный файл создан."

# 2. Создаем скрипт для if-up.d
echo -e "${YELLOW}[2] Создаем /etc/network/if-up.d/vpn-routing...${NC}"
cat > /etc/network/if-up.d/vpn-routing <<'EOF'
#!/bin/bash
set -e

# Загружаем конфигурацию
[ -f /etc/network/vpn-routing.conf ] && source /etc/network/vpn-routing.conf

# Применяем правила только для ppp* интерфейсов
if [[ "$IFACE" =~ ^ppp[0-9]+$ ]]; then
    # Ждем 2 секунды, чтобы интерфейс полностью поднялся
    sleep 2

    # Получаем подсеть интерфейса
    ppp_subnet=$(ip -o -f inet addr show $IFACE | awk '{print $4}' | sed 's/\/.*//' | awk -F'.' '{print $1"."$2"."$3".0/24"}')

    # Добавляем правило маршрутизации
    ip rule add from $ppp_subnet lookup $TABLE_NAME 2>/dev/null || true

    # Разрешаем пересылку
    iptables -C FORWARD -i $IFACE -o $VPN_IFACE -j ACCEPT 2>/dev/null || iptables -A FORWARD -i $IFACE -o $VPN_IFACE -j ACCEPT
    iptables -C FORWARD -i $VPN_IFACE -o $IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i $VPN_IFACE -o $IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

    logger "VPN Routing: Added rules for $IFACE ($ppp_subnet)"
fi
EOF
check_error "Не удалось создать if-up скрипт." "if-up скрипт создан."

# 3. Создаем скрипт для if-down.d
echo -e "${YELLOW}[3] Создаем /etc/network/if-down.d/vpn-routing...${NC}"
cat > /etc/network/if-down.d/vpn-routing <<'EOF'
#!/bin/bash
set -e

# Загружаем конфигурацию
[ -f /etc/network/vpn-routing.conf ] && source /etc/network/vpn-routing.conf

# Удаляем правила только для ppp* интерфейсов
if [[ "$IFACE" =~ ^ppp[0-9]+$ ]]; then
    # Получаем подсеть интерфейса
    ppp_subnet=$(ip -o -f inet addr show $IFACE | awk '{print $4}' | sed 's/\/.*//' | awk -F'.' '{print $1"."$2"."$3".0/24"}')

    # Удаляем правило маршрутизации
    ip rule del from $ppp_subnet lookup $TABLE_NAME 2>/dev/null || true

    # Удаляем правила FORWARD
    iptables -D FORWARD -i $IFACE -o $VPN_IFACE -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i $VPN_IFACE -o $IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    logger "VPN Routing: Removed rules for $IFACE ($ppp_subnet)"
fi
EOF
check_error "Не удалось создать if-down скрипт." "if-down скрипт создан."

# 4. Делаем скрипты исполняемыми
echo -e "${YELLOW}[4] Даем права на выполнение...${NC}"
chmod +x /etc/network/if-up.d/vpn-routing
chmod +x /etc/network/if-down.d/vpn-routing
check_error "Не удалось установить права." "Права на выполнение установлены."

# 5. Настраиваем таблицу маршрутизации
echo -e "${YELLOW}[5] Настраиваем таблицу маршрутизации...${NC}"
if ! grep -q "$TABLE_NAME" /etc/iproute2/rt_tables; then
    echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables
    check_error "Не удалось добавить таблицу маршрутизации." "Таблица маршрутизации добавлена."
else
    echo -e "${GREEN}[OK]${NC} Таблица маршрутизации уже существует."
fi

# 6. Добавляем маршруты
echo -e "${YELLOW}[6] Добавляем маршруты...${NC}"
ip route add default via $VPN_GATEWAY dev $VPN_IFACE table $TABLE_NAME 2>/dev/null || true
ip route add $VPN_NETWORK dev $VPN_IFACE table $TABLE_NAME 2>/dev/null || true
ip route add $MAIN_NETWORK dev $MAIN_IFACE table $TABLE_NAME 2>/dev/null || true
check_error "Не удалось добавить маршруты." "Маршруты добавлены."

# 7. Настраиваем iptables
echo -e "${YELLOW}[7] Настраиваем iptables...${NC}"
iptables -t nat -A POSTROUTING -o $VPN_IFACE -j MASQUERADE
iptables -A FORWARD -i ppp+ -o $VPN_IFACE -j ACCEPT
iptables -A FORWARD -i $VPN_IFACE -o ppp+ -m state --state RELATED,ESTABLISHED -j ACCEPT
check_error "Не удалось настроить iptables." "Правила iptables добавлены."

# 8. Устанавливаем iptables-persistent
echo -e "${YELLOW}[8] Устанавливаем iptables-persistent...${NC}"
if ! command -v netfilter-persistent >/dev/null; then
    apt-get update && apt-get install -y iptables-persistent
    check_error "Не удалось установить iptables-persistent." "iptables-persistent установлен."
else
    echo -e "${GREEN}[OK]${NC} iptables-persistent уже установлен."
fi

# 9. Сохраняем правила
echo -e "${YELLOW}[9] Сохраняем правила iptables...${NC}"
netfilter-persistent save
check_error "Не удалось сохранить правила." "Правила iptables сохранены."

# 10. Настраиваем автозагрузку
echo -e "${YELLOW}[10] Настраиваем автозагрузку...${NC}"

# Создаем systemd сервис для инициализации маршрутов
cat > /etc/systemd/system/vpn-routing-init.service <<EOF
[Unit]
Description=VPN Routing Initialization
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'source /etc/network/vpn-routing.conf; \
ip route add default via \$VPN_GATEWAY dev \$VPN_IFACE table \$TABLE_NAME 2>/dev/null || true; \
ip route add \$VPN_NETWORK dev \$VPN_IFACE table \$TABLE_NAME 2>/dev/null || true; \
ip route add \$MAIN_NETWORK dev \$MAIN_IFACE table \$TABLE_NAME 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF

# Включаем и запускаем сервис
systemctl daemon-reload
systemctl enable vpn-routing-init.service
systemctl start vpn-routing-init.service

check_error "Не удалось настроить автозагрузку." "Автозагрузка настроена через systemd."

echo -e "${GREEN}\nНастройка завершена успешно!${NC}"
echo -e "Правила будут автоматически применяться при появлении ppp-интерфейсов."