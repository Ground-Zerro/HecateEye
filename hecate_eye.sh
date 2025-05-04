#!/bin/bash
set -e

read -p "Введите VLESS-ссылку (начиная с vless://): " vless_url

fragment=${vless_url#*#}
name=$(printf '%b' "${fragment//%/\\x}")
url_body=${vless_url#vless://}
uuid=${url_body%%@*}
hostport_and_params=${url_body#*@}
hostport=${hostport_and_params%%\?*}
raw_params=${hostport_and_params#*\?}
raw_params=${raw_params%%#*}
server=${hostport%%:*}
port=${hostport#*:}

get_param() {
  echo "$raw_params" | tr '&' '\n' | grep "^$1=" | cut -d'=' -f2-
}

flow=$(get_param flow)
pbk=$(get_param pbk)
sid=$(get_param sid)
sni=$(get_param sni)
fp=$(get_param fp)

if [[ -z "$uuid" || -z "$server" || -z "$port" || -z "$flow" || -z "$pbk" || -z "$sid" || -z "$sni" || -z "$fp" || -z "$name" ]]; then
    echo "[!] Ошибка: Не удалось извлечь все необходимые параметры из ссылки"
    exit 1
fi

echo "[+] Извлечено:"
echo "    tag:               $name"
echo "    server:            $server"
echo "    port:              $port"
echo "    uuid:              $uuid"
echo "    flow:              $flow"
echo "    packet_encoding:   xudp"
echo "    domain_strategy:   ipv4_only"
echo "    tls.utls.fp:       $fp"
echo "    tls.reality.pbk:   $pbk"
echo "    tls.reality.sid:   $sid"
echo "    tls.server_name:   $sni"
echo

echo "[+] Загружаем модуль tun..."
sudo modprobe tun

echo "[+] Обновляем apt и ставим софт..."
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iputils-ping curl dnsutils ipcalc tcpdump jq

echo "[+] Отключаем systemd-resolved и настраиваем /etc/resolv.conf..."
sudo systemctl disable --now systemd-resolved || true
sudo rm -f /etc/resolv.conf
echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" | sudo tee /etc/resolv.conf > /dev/null

echo "[+] Загружаем и устанавливаем sing-box v1.11.9..."
wget -q https://github.com/sagernet/sing-box/releases/download/v1.11.9/sing-box_1.11.9_linux_amd64.deb -O /tmp/sing-box.deb
sudo dpkg -i /tmp/sing-box.deb
rm -f /tmp/sing-box.deb

echo "[+] Создаём каталог /etc/sing-box..."
sudo mkdir -p /etc/sing-box

echo "[+] Генерируем /etc/sing-box/config.json..."
sudo tee /etc/sing-box/config.json > /dev/null <<EOF
{
  "log": {
    "disabled": true
  },
  "inbounds": [
    {
      "type": "tun",
      "interface_name": "tun0",
      "address": ["10.10.10.2/24"],
      "mtu": 9000,
      "auto_route": false,
      "strict_route": false,
      "domain_strategy": "ipv4_only",
      "endpoint_independent_nat": true,
      "sniff": false,
      "stack": "gvisor",
      "tag": "tun-in-tun0"
    },
    {
      "type": "mixed",
      "tag": "mixed-in-tun0",
      "listen": "0.0.0.0",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "$name",
      "server": "$server",
      "server_port": $port,
      "uuid": "$uuid",
      "flow": "$flow",
      "packet_encoding": "xudp",
      "domain_strategy": "ipv4_only",
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
      }
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": "tun-in-tun0",
        "action": "route",
        "outbound": "$name"
      },
      {
        "inbound": "mixed-in-tun0",
        "action": "route",
        "outbound": "$name"
      },
      {
        "action": "reject"
      }
    ],
    "auto_detect_interface": false
  }
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

echo "[+] Проверяем результат..."
if ip link show tun0 &>/dev/null; then
  echo "[✓] Интерфейс tun0 создан."
else
  echo "[✗] tun0 не найден. Смотрим логи:"
  journalctl -u sing-box --no-pager -n 20
  exit 1
fi

if ip_tun=$(curl --interface tun0 -s https://api.ipify.org) && [[ -n "$ip_tun" ]]; then
  echo "[✓] IP (через туннель): $ip_tun"
else
  echo "[✗] Не удалось получить IP через tun0"
  exit 1
fi

if ip_direct=$(curl -s https://api.ipify.org) && [[ -n "$ip_direct" ]]; then
  echo "[✓] IP (напрямую): $ip_direct"
else
  echo "[✗] Не удалось получить прямой IP"
  exit 1
fi

echo "[+] Устанвока завершена успешно."