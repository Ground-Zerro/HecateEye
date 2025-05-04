#!/bin/bash
set -e

echo "[+] Загружаем модуль tun..."
sudo modprobe tun

echo "[+] Обновляем apt и ставим ping, curl, dnsutils..."
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iputils-ping curl dnsutils jq

echo "[+] Отключаем systemd-resolved и настраиваем /etc/resolv.conf..."
sudo systemctl disable --now systemd-resolved || true
sudo rm -f /etc/resolv.conf
echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" | sudo tee /etc/resolv.conf > /dev/null

read -p "Введите VLESS‑ссылку (начиная с vless://): " vless_url

url_body=${vless_url#vless://}
uuid=$(echo "$url_body" | cut -d'@' -f1)
hostport_and_params=$(echo "$url_body" | cut -d'@' -f2)

hostport=$(echo "$hostport_and_params" | cut -d'?' -f1)
raw_params=$(echo "$hostport_and_params" | cut -d'?' -f2 | cut -d'#' -f1)

server=$(echo "$hostport" | cut -d':' -f1)
port=$(echo "$hostport" | cut -d':' -f2)

get_param() {
  echo "$raw_params" | tr '&' '\n' | grep "^$1=" | cut -d'=' -f2-
}

flow=$(get_param flow)
pbk=$(get_param pbk)
sid=$(get_param sid)
sni=$(get_param sni)
fp=$(get_param fp)

if [[ -z "$uuid" || -z "$server" || -z "$port" || -z "$pbk" || -z "$sid" || -z "$sni" || -z "$fp" || -z "$flow" ]]; then
    echo "[!] Ошибка: Не удалось извлечь все необходимые параметры из ссылки"
    exit 1
fi

echo "[+] Загружаем и устанавливаем sing-box v1.11.9..."
wget -q https://github.com/sagernet/sing-box/releases/download/v1.11.9/sing-box_1.11.9_linux_amd64.deb -O /tmp/sing-box.deb
sudo dpkg -i /tmp/sing-box.deb
rm -f /tmp/sing-box.deb

echo "[+] Создаём каталог /etc/sing-box..."
sudo mkdir -p /etc/sing-box

echo "[+] Генерируем /etc/sing-box/config.json..."
sudo tee /etc/sing-box/config.json > /dev/null <<EOF
{
  "log": { "level": "info" },
  "dns": {
    "servers": [
      {
        "address": "tls://dns.quad9.net",
        "address_resolver": "local-dns",
        "detour": "vless-out"
      },
      {
        "address": "tls://dns.google",
        "address_resolver": "local-dns",
        "detour": "vless-out"
      },
      {
        "tag": "local-dns",
        "address": "1.1.1.1",
        "detour": "direct-out"
      }
    ],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "address": ["10.10.10.2/24"],
      "mtu": 1500,
      "auto_route": false,
      "auto_redirect": false
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-out",
      "server": "$server",
      "server_port": $port,
      "uuid": "$uuid",
      "flow": "$flow",
      "network": "tcp",
      "tls": {
        "enabled": true,
        "server_name": "$sni",
        "utls": {
          "enabled": true,
          "fingerprint": "$fp"
        },
        "reality": {
          "enabled": true,
          "public_key": "$pbk",
          "short_id": "$sid"
        }
      },
      "multiplex": {}
    },
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ]
}
EOF

echo "[+] Создаём /etc/systemd/system/sing-box.service..."
sudo tee /etc/systemd/system/sing-box.service > /dev/null <<EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
ExecStartPre=/sbin/modprobe tun
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
User=root
LimitNOFILE=4096
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

echo "[+] Перезагружаем демоны systemd и стартуем sing-box..."
sudo systemctl daemon-reload
sudo systemctl enable --now sing-box

sleep 2

if ip link show tun0 &>/dev/null; then
  echo "[+] Интерфейс tun0 создан."
else
  echo "[!] tun0 не найден. Смотрим логи:"
  journalctl -u sing-box --no-pager -n 20
  exit 1
fi

echo -e "\n[+] Пинг 8.8.8.8 через tun0..."
ping -I tun0 -c 4 8.8.8.8

echo -e "\n[+] Пинг 8.8.8.8 через систему..."
ping -I tun0 -c 4 8.8.8.8

echo -e "\n[+] Резолвим и пингуем ya.ru через tun0..."
ping -I tun0 -c 4 ya.ru

echo -e "\n[+] Резолвим и пингуем ya.ru через системный резолвер..."
ping -I tun0 -c 4 ya.ru

echo -e "\n[+] IP (api.ipify.org) через туннель:"
curl --interface tun0 -s https://api.ipify.org && echo

echo -e "\n[+] IP (api.ipify.org) напрямую:"
curl -s https://api.ipify.org && echo

echo -e "\n[+] Если пинги прошли и вы увидели IP — всё работает."
