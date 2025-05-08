#!/bin/bash

set -e

# === Конфигурация ===
TABLE_ID=100
TABLE_NAME="ppp_via_vpn"
MARK_ID=100
VPN_INTERFACE="tun0"
NFT_TABLE="inet mangle"
NFT_CHAIN="prerouting"

# === Проверка root ===
if [[ $EUID -ne 0 ]]; then
   echo "Скрипт должен запускаться от root." 
   exit 1
fi

# === Проверка необходимых утилит ===
echo "[*] Проверка необходимых утилит..."

if ! command -v ip &> /dev/null; then
    echo "[+] Установка iproute2..."
    apt update && apt install -y iproute2
fi

if ! command -v nft &> /dev/null; then
    echo "[+] Установка nftables..."
    apt update && apt install -y nftables
    systemctl enable nftables
    systemctl start nftables
fi

# === Добавление таблицы маршрутов ===
echo "[*] Настройка таблицы маршрутов $TABLE_ID ($TABLE_NAME)..."
grep -q "$TABLE_ID[[:space:]]$TABLE_NAME" /etc/iproute2/rt_tables || \
    echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables

ip route replace default dev "$VPN_INTERFACE" table "$TABLE_ID"

# === Добавление ip rule по fwmark ===
if ! ip rule list | grep -q "fwmark $MARK_ID lookup $TABLE_ID"; then
    echo "[*] Добавление ip rule для fwmark..."
    ip rule add fwmark "$MARK_ID" table "$TABLE_ID"
fi

# === Настройка nftables ===
echo "[*] Настройка nftables маркировки трафика с pppX..."

nft list table $NFT_TABLE > /dev/null 2>&1 || \
    nft add table $NFT_TABLE

# Очистка и пересоздание цепочки
nft flush chain $NFT_TABLE $NFT_CHAIN 2>/dev/null || true
nft delete chain $NFT_TABLE $NFT_CHAIN 2>/dev/null || true

nft add chain $NFT_TABLE $NFT_CHAIN { type filter hook prerouting priority mangle \; }

# Добавляем правило маркировки
nft add rule $NFT_TABLE $NFT_CHAIN iifname "ppp*" meta mark set $MARK_ID

# === Готово ===
echo "[✔] Трафик с интерфейсов pppX теперь маршрутизируется через $VPN_INTERFACE (таблица $TABLE_ID)."