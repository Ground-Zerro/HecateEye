#!/bin/bash

# Конфигурация
TABLE_ID=200
TABLE_NAME=vpnroute
VPN_IFACE=tun0
CONFIG_FILE="/etc/network/vpn-routing.conf"

YELLOW="\e[33m"
GREEN="\e[32m"
RED="\e[31m"
NC="\e[0m"

# Проверка и установка ipcalc
if ! command -v ipcalc &> /dev/null; then
    echo -e "${YELLOW}[*] Утилита ipcalc не найдена. Устанавливаем...${NC}"
    apt update && apt install -y ipcalc
    if ! command -v ipcalc &> /dev/null; then
        echo -e "${RED}[Ошибка] Не удалось установить ipcalc. Прекращаю выполнение.${NC}"
        exit 1
    fi
    echo -e "${GREEN}ipcalc успешно установлен.${NC}"
fi

# Проверка, что интерфейс VPN поднят
if ! ip link show "$VPN_IFACE" &> /dev/null || ! ip -o -f inet addr show "$VPN_IFACE" | grep -q inet; then
    echo -e "${RED}[Ошибка] Интерфейс $VPN_IFACE не существует или не имеет IP-адреса.${NC}"
    exit 1
fi

# Автоопределение VPN параметров
VPN_CIDR=$(ip -o -f inet addr show "$VPN_IFACE" | awk '{print $4}')
VPN_GATEWAY=$(echo "$VPN_CIDR" | cut -d/ -f1)
VPN_NETWORK=$(ipcalc -n "$VPN_CIDR" | awk '/Network/ {print $2}')

# Автоопределение основного интерфейса и сети
MAIN_IFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
MAIN_CIDR=$(ip -o -f inet addr show "$MAIN_IFACE" | awk '{print $4}')
MAIN_NETWORK=$(ipcalc -n "$MAIN_CIDR" | awk '/Network/ {print $2}')

echo -e "${YELLOW}[*] Создаём таблицу маршрутизации...${NC}"
if ! grep -q "$TABLE_NAME" /etc/iproute2/rt_tables; then
    echo "$TABLE_ID    $TABLE_NAME" >> /etc/iproute2/rt_tables
    echo -e "${GREEN}Добавлена таблица маршрутизации $TABLE_NAME с ID $TABLE_ID${NC}"
else
    echo -e "${GREEN}Таблица маршрутизации $TABLE_NAME уже существует${NC}"
fi

echo -e "${YELLOW}[*] Генерируем конфигурационный файл...${NC}"
cat > "$CONFIG_FILE" <<EOF
TABLE_ID=$TABLE_ID
TABLE_NAME=$TABLE_NAME
VPN_IFACE=$VPN_IFACE
VPN_GATEWAY=$VPN_GATEWAY
VPN_NETWORK=$VPN_NETWORK
MAIN_IFACE=$MAIN_IFACE
MAIN_NETWORK=$MAIN_NETWORK
EOF
echo -e "${GREEN}Конфигурация сохранена в $CONFIG_FILE${NC}"

echo -e "${YELLOW}[*] Настраиваем PPPX-интерфейсы...${NC}"
for iface in $(ls /sys/class/net/ | grep '^ppp'); do
    IP=$(ip -o -f inet addr show "$iface" | awk '{print $4}')
    [[ -z "$IP" ]] && continue
    SUBNET=$(ipcalc -n "$IP" | awk '/Network/ {print $2}')
    echo -e "${GREEN}[+] Обработка интерфейса $iface${NC}"
    echo "  Подсеть: $SUBNET"

    # Добавление правила, если отсутствует
    if ! ip rule list | grep -q "$SUBNET.*lookup $TABLE_NAME"; then
        ip rule add from "$SUBNET" table "$TABLE_NAME"
        echo "  Добавлено правило маршрутизации для $SUBNET -> $TABLE_NAME"
    else
        echo "  Правило уже существует"
    fi
done

echo -e "${YELLOW}[*] Добавляем маршруты в таблицу $TABLE_NAME...${NC}"
# Default маршрут через VPN
if ! ip route show table "$TABLE_NAME" | grep -q "^default via $VPN_GATEWAY"; then
    ip route add default via "$VPN_GATEWAY" dev "$VPN_IFACE" table "$TABLE_NAME" 2>/dev/null || \
    echo -e "${RED}  [!] Не удалось добавить default маршрут${NC}"
    echo "  Добавлен маршрут default через $VPN_GATEWAY"
else
    echo "  Default маршрут уже существует"
fi

# VPN-сеть
if ! ip route show table "$TABLE_NAME" | grep -q "^$VPN_NETWORK"; then
    ip route add "$VPN_NETWORK" dev "$VPN_IFACE" table "$TABLE_NAME"
    echo "  Добавлен маршрут для VPN-сети"
fi

# Основная сеть
if ! ip route show table "$TABLE_NAME" | grep -q "^$MAIN_NETWORK"; then
    ip route add "$MAIN_NETWORK" dev "$MAIN_IFACE" table "$TABLE_NAME"
    echo "  Добавлен маршрут для основной сети"
fi

echo -e "${YELLOW}[*] Настраиваем iptables NAT...${NC}"
if ! iptables -t nat -C POSTROUTING -o "$VPN_IFACE" -j MASQUERADE &>/dev/null; then
    iptables -t nat -A POSTROUTING -o "$VPN_IFACE" -j MASQUERADE
    echo "  MASQUERADE добавлен"
else
    echo "  MASQUERADE уже настроен"
fi

echo -e "${GREEN}Настройка завершена успешно.${NC}"