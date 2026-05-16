#!/usr/bin/env bash
set -euo pipefail

#################################
# TRAP
#################################
trap 'echo -e "\033[1;31m[ERROR]\033[0m Ошибка в строке $LINENO"; exit 1' ERR

#################################
# HELPERS
#################################
log() { echo -e "\033[1;32m[INFO]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
die() { echo -e "\033[1;31m[ERROR]\033[0m $1"; exit 1; }

[[ $EUID -eq 0 ]] || die "Запускать нужно от root"

. /etc/os-release
[[ "$ID" == "ubuntu" || "$ID" == "debian" ]] || die "Только Ubuntu/Debian: $ID"

#################################
# ASCII-баннер
#################################
echo "==================================================="
echo "     БЕЗОПАСНЫЙ FORWARDING С МНОЖЕСТВЕННЫМИ IP    "
echo "==================================================="
echo ""

#################################
# Проверка UFW
#################################
command -v ufw >/dev/null 2>&1 || die "UFW не установлен. Установите: apt install ufw"

if ! LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"; then
    warn "UFW не активен. Активируйте его вручную перед запуском скрипта."
    die "Выполните: ufw enable"
fi

#################################
# Проверка ip_forward
#################################
if ! grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null; then
    warn "ip_forward не включён. Включаю..."
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.d/99-forwarding.conf
    sysctl -w net.ipv4.ip_forward=1
else
    log "ip_forward уже включён"
fi

#################################
# Ввод данных
#################################
LOCAL_IP=$(hostname -I | awk '{print $1}')
log "Локальный IP: $LOCAL_IP"
echo ""

# Ввод origin IP адресов
ORIGIN_IPS=()
echo "Введите IP адреса origin серверов (по одному, пустая строка для завершения):"
while true; do
    read -p "Origin IP #$((${#ORIGIN_IPS[@]} + 1)): " ip
    [[ -z "$ip" ]] && break
    
    # Проверка валидности IP
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        warn "Невалидный IP: $ip, попробуйте снова"
        continue
    fi
    
    ORIGIN_IPS+=("$ip")
    log "Добавлен: $ip"
done

[[ ${#ORIGIN_IPS[@]} -eq 0 ]] && die "Нужен минимум один origin IP"
echo ""

# Ввод портов
echo "Введите порты для форвардинга (через пробел, например: 2053 8080 10000-20000):"
read -p "Порты: " PORTS_INPUT
[[ -z "$PORTS_INPUT" ]] && die "Порты не указаны"

# Выбор протокола
echo ""
echo "Выберите протокол:"
echo "1) TCP"
echo "2) UDP"  
echo "3) TCP+UDP"
read -p "Выбор [1-3]: " PROTO_CHOICE

case $PROTO_CHOICE in
    1) PROTOCOLS=("tcp") ;;
    2) PROTOCOLS=("udp") ;;
    3) PROTOCOLS=("tcp" "udp") ;;
    *) die "Невалидный выбор" ;;
esac

#################################
# Проверка конфликтов портов
#################################
log "Проверка конфликтов с занятыми портами..."
CONFLICTS=()

for port_spec in $PORTS_INPUT; do
    if [[ $port_spec =~ ^([0-9]+)-([0-9]+)$ ]]; then
        # Диапазон портов - проверяем начало и конец
        start=${BASH_REMATCH[1]}
        end=${BASH_REMATCH[2]}
        for p in $start $end; do
            for proto in "${PROTOCOLS[@]}"; do
                if ss -"${proto:0:1}"ln | grep -q ":$p "; then
                    CONFLICTS+=("$p/$proto")
                fi
            done
        done
    else
        # Один порт
        for proto in "${PROTOCOLS[@]}"; do
            if ss -"${proto:0:1}"ln | grep -q ":$port_spec "; then
                CONFLICTS+=("$port_spec/$proto")
            fi
        done
    fi
done

if [[ ${#CONFLICTS[@]} -gt 0 ]]; then
    warn "ВНИМАНИЕ! Следующие порты уже заняты:"
    printf '%s\n' "${CONFLICTS[@]}"
    echo ""
    read -p "Продолжить форвардинг занятых портов? Это может сломать работу сервисов! [y/N]: " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && die "Отменено пользователем"
fi

#################################
# Создание правил в отдельном файле
#################################
RULES_FILE="/etc/ufw/relay-forwarding.rules"

log "Создание правил в $RULES_FILE..."

cat > "$RULES_FILE" <<EOF
# Relay forwarding rules - создано $(date)
# Origin IPs: ${ORIGIN_IPS[*]}
# Ports: $PORTS_INPUT
# Protocols: ${PROTOCOLS[*]}
# SECURITY: Ports are CLOSED for direct connections, OPEN only for forwarding to origin IPs

*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

EOF

# Генерация правил для каждого origin IP
for origin_ip in "${ORIGIN_IPS[@]}"; do
    echo "# Rules for $origin_ip" >> "$RULES_FILE"
    
    for proto in "${PROTOCOLS[@]}"; do
        proto_upper=$(echo "$proto" | tr '[:lower:]' '[:upper:]')
        
        # DNAT
        echo "-A PREROUTING -p $proto -m multiport --dports $PORTS_INPUT -j DNAT --to-destination $origin_ip" >> "$RULES_FILE"
        
        # SNAT
        echo "-A POSTROUTING -p $proto -d $origin_ip -j SNAT --to-source $LOCAL_IP" >> "$RULES_FILE"
    done
    
    echo "" >> "$RULES_FILE"
done

cat >> "$RULES_FILE" <<EOF
COMMIT

*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]

# SECURITY: Блокируем прямые подключения к портам форвардинга
# Эти порты доступны ТОЛЬКО для форвардинга на origin IP
EOF

for proto in "${PROTOCOLS[@]}"; do
    echo "-A INPUT -p $proto -m multiport --dports $PORTS_INPUT -j DROP" >> "$RULES_FILE"
done

cat >> "$RULES_FILE" <<EOF

# Разрешаем форвардинг ТОЛЬКО для origin серверов
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

EOF

for origin_ip in "${ORIGIN_IPS[@]}"; do
    echo "-A FORWARD -d $origin_ip -j ACCEPT" >> "$RULES_FILE"
    echo "-A FORWARD -s $origin_ip -j ACCEPT" >> "$RULES_FILE"
done

# Блокируем форвардинг на эти порты для всех остальных IP
for proto in "${PROTOCOLS[@]}"; do
    echo "-A FORWARD -p $proto -m multiport --dports $PORTS_INPUT -j DROP" >> "$RULES_FILE"
done

cat >> "$RULES_FILE" <<EOF

COMMIT
EOF

log "Правила созданы в $RULES_FILE"

#################################
# Включение правил в before.rules
#################################
BEFORE_RULES="/etc/ufw/before.rules"

if grep -q "relay-forwarding.rules" "$BEFORE_RULES"; then
    warn "Include уже существует в before.rules"
else
    log "Добавление include в before.rules..."
    
    # Бэкап
    cp "$BEFORE_RULES" "${BEFORE_RULES}.bak.$(date +%s)"
    
    # Добавляем include в начало файла (после shebang)
    sed -i "1a # Include relay forwarding rules\n@include $RULES_FILE\n" "$BEFORE_RULES"
    
    log "Include добавлен"
fi

#################################
# НЕ открываем порты в UFW (SECURITY)
#################################
warn "БЕЗОПАСНОСТЬ: Порты НЕ открываются в UFW"
warn "Прямые подключения к портам форвардинга ЗАБЛОКИРОВАНЫ"
log "Форвардинг работает ТОЛЬКО для origin IP: ${ORIGIN_IPS[*]}"
echo ""

#################################
# Проверка FORWARD policy
#################################
if grep -q "DEFAULT_FORWARD_POLICY=\"DROP\"" /etc/default/ufw; then
    warn "FORWARD policy = DROP. Меняю на ACCEPT..."
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    log "FORWARD policy изменён на ACCEPT"
else
    log "FORWARD policy уже настроен корректно"
fi

#################################
# Перезапуск UFW
#################################
log "Перезапуск UFW..."
ufw reload

#################################
# Вывод результата
#################################
echo ""
echo "==================================================="
log "Форвардинг настроен успешно!"
echo "==================================================="
echo ""
echo "Origin серверы: ${ORIGIN_IPS[*]}"
echo "Порты: $PORTS_INPUT"
echo "Протоколы: ${PROTOCOLS[*]}"
echo ""
echo "Файл правил: $RULES_FILE"
echo "Бэкап before.rules: ${BEFORE_RULES}.bak.*"
echo ""
warn "Для удаления форвардинга:"
echo "1. Удалите строку @include из $BEFORE_RULES"
echo "2. Удалите файл $RULES_FILE"
echo "3. Выполните: ufw reload"
echo ""
