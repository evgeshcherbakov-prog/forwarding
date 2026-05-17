#!/usr/bin/env bash
set -euo pipefail

#################################
# TRAP
#################################
trap 'echo -e "\033[1;31m[ERROR]\033[0m Ошибка в строке $LINENO. Откат изменений..."; [[ -f "$BEFORE_RULES.bak.temp" ]] && mv "$BEFORE_RULES.bak.temp" "$BEFORE_RULES" && ufw reload; exit 1' ERR

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
# Генерация правил
#################################
BEFORE_RULES="/etc/ufw/before.rules"
MARKER_START="# === RELAY FORWARDING START ==="
MARKER_END="# === RELAY FORWARDING END ==="

# Проверка существующих правил
if grep -q "$MARKER_START" "$BEFORE_RULES"; then
    warn "Правила форвардинга уже существуют!"
    read -p "Перезаписать существующие правила? [y/N]: " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && die "Отменено пользователем"
    
    # Удаление старых правил
    log "Удаление старых правил..."
    sed -i "/$MARKER_START/,/$MARKER_END/d" "$BEFORE_RULES"
fi

# Создание временного бэкапа
cp "$BEFORE_RULES" "${BEFORE_RULES}.bak.temp"

log "Генерация правил форвардинга..."

# Генерация NAT правил
NAT_RULES=$(cat <<EOF

$MARKER_START
# Relay forwarding rules - создано $(date)
# Origin IPs: ${ORIGIN_IPS[*]}
# Ports: $PORTS_INPUT
# Protocols: ${PROTOCOLS[*]}
# SECURITY: Ports are CLOSED for direct connections, OPEN only for forwarding to origin IPs

EOF
)

for origin_ip in "${ORIGIN_IPS[@]}"; do
    NAT_RULES+="# Rules for $origin_ip"$'\n'
    
    for proto in "${PROTOCOLS[@]}"; do
        # DNAT
        NAT_RULES+="-A PREROUTING -p $proto -m multiport --dports $PORTS_INPUT -j DNAT --to-destination $origin_ip"$'\n'
        
        # SNAT
        NAT_RULES+="-A POSTROUTING -p $proto -d $origin_ip -j SNAT --to-source $LOCAL_IP"$'\n'
    done
    
    NAT_RULES+=$'\n'
done

NAT_RULES+="$MARKER_END"$'\n'

# Генерация FILTER правил
FILTER_RULES=$(cat <<EOF

$MARKER_START
# SECURITY: Блокируем прямые подключения к портам форвардинга
# Эти порты доступны ТОЛЬКО для форвардинга на origin IP

EOF
)

# INPUT DROP правила
for proto in "${PROTOCOLS[@]}"; do
    FILTER_RULES+="-A INPUT -p $proto -m multiport --dports $PORTS_INPUT -j DROP"$'\n'
done

FILTER_RULES+=$'\n'
FILTER_RULES+="# Разрешаем форвардинг ТОЛЬКО для origin серверов"$'\n'

# FORWARD ACCEPT для origin IP
for origin_ip in "${ORIGIN_IPS[@]}"; do
    FILTER_RULES+="-A FORWARD -d $origin_ip -j ACCEPT"$'\n'
    FILTER_RULES+="-A FORWARD -s $origin_ip -j ACCEPT"$'\n'
done

FILTER_RULES+=$'\n'
FILTER_RULES+="# Блокируем форвардинг на эти порты для всех остальных IP"$'\n'

# FORWARD DROP для остальных
for proto in "${PROTOCOLS[@]}"; do
    FILTER_RULES+="-A FORWARD -p $proto -m multiport --dports $PORTS_INPUT -j DROP"$'\n'
done

FILTER_RULES+=$'\n'
FILTER_RULES+="$MARKER_END"$'\n'

#################################
# Вставка правил в before.rules
#################################
log "Вставка правил в before.rules..."

# Найти позицию COMMIT в таблице *nat
NAT_COMMIT_LINE=$(grep -n "^COMMIT" "$BEFORE_RULES" | head -1 | cut -d: -f1)

if [[ -z "$NAT_COMMIT_LINE" ]]; then
    die "Не найдена секция *nat в before.rules"
fi

# Вставить NAT правила перед первым COMMIT
sed -i "${NAT_COMMIT_LINE}i\\
$NAT_RULES" "$BEFORE_RULES"

# Найти позицию второго COMMIT (для *filter)
FILTER_COMMIT_LINE=$(grep -n "^COMMIT" "$BEFORE_RULES" | sed -n '2p' | cut -d: -f1)

if [[ -z "$FILTER_COMMIT_LINE" ]]; then
    die "Не найдена секция *filter в before.rules"
fi

# Вставить FILTER правила перед вторым COMMIT
sed -i "${FILTER_COMMIT_LINE}i\\
$FILTER_RULES" "$BEFORE_RULES"

log "Правила добавлены в before.rules"

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
if ! ufw reload; then
    die "Ошибка при применении правил. Восстановление из бэкапа..."
fi

# Удаление временного бэкапа при успехе
rm -f "${BEFORE_RULES}.bak.temp"

# Создание постоянного бэкапа
cp "$BEFORE_RULES" "${BEFORE_RULES}.bak.$(date +%s)"

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
echo "Правила добавлены в: $BEFORE_RULES"
echo "Бэкап создан: ${BEFORE_RULES}.bak.*"
echo ""
warn "Для удаления форвардинга:"
echo "sudo ./remove_forwarding.sh"
echo ""
warn "Для проверки безопасности:"
echo "sudo ./test_security.sh"
echo ""
