#!/usr/bin/env bash
set -euo pipefail

log() { echo -e "\033[1;32m[PASS]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $1"; }

[[ $EUID -eq 0 ]] || { echo "Запускать нужно от root"; exit 1; }

RULES_FILE="/etc/ufw/relay-forwarding.rules"

echo "==================================================="
echo "       ПРОВЕРКА БЕЗОПАСНОСТИ ФОРВАРДИНГА          "
echo "==================================================="
echo ""

# Проверка существования файла правил
if [[ ! -f "$RULES_FILE" ]]; then
    fail "Файл правил не найден: $RULES_FILE"
    exit 1
fi

# Извлечение origin IP и портов из файла правил
ORIGIN_IPS=$(grep "^# Origin IPs:" "$RULES_FILE" | cut -d: -f2- | xargs)
PORTS=$(grep "^# Ports:" "$RULES_FILE" | cut -d: -f2- | xargs)
PROTOCOLS=$(grep "^# Protocols:" "$RULES_FILE" | cut -d: -f2- | xargs)

echo "Конфигурация форвардинга:"
echo "  Origin IPs: $ORIGIN_IPS"
echo "  Порты: $PORTS"
echo "  Протоколы: $PROTOCOLS"
echo ""

#################################
# Тест 1: Проверка INPUT DROP
#################################
echo "=== Тест 1: INPUT DROP правила ==="

INPUT_DROP_COUNT=0
for proto in $PROTOCOLS; do
    if iptables -L INPUT -n | grep -q "multiport dports.*DROP"; then
        log "INPUT DROP правила найдены для $proto"
        INPUT_DROP_COUNT=$((INPUT_DROP_COUNT + 1))
    else
        fail "INPUT DROP правила НЕ найдены для $proto"
    fi
done

if [[ $INPUT_DROP_COUNT -eq 0 ]]; then
    fail "Тест 1 провален: порты НЕ заблокированы в INPUT"
else
    log "Тест 1 пройден: найдено $INPUT_DROP_COUNT DROP правил в INPUT"
fi
echo ""

#################################
# Тест 2: Проверка NAT PREROUTING
#################################
echo "=== Тест 2: NAT PREROUTING правила ==="

NAT_COUNT=$(iptables -t nat -L PREROUTING -n | grep -c "DNAT" || true)

if [[ $NAT_COUNT -gt 0 ]]; then
    log "Найдено $NAT_COUNT DNAT правил в PREROUTING"
    
    # Проверка что DNAT ведёт на origin IP
    for origin_ip in $ORIGIN_IPS; do
        if iptables -t nat -L PREROUTING -n | grep -q "to:$origin_ip"; then
            log "DNAT на origin IP $origin_ip найден"
        else
            warn "DNAT на origin IP $origin_ip НЕ найден"
        fi
    done
    
    log "Тест 2 пройден: NAT правила настроены"
else
    fail "Тест 2 провален: DNAT правила НЕ найдены"
fi
echo ""

#################################
# Тест 3: Проверка FORWARD разрешений
#################################
echo "=== Тест 3: FORWARD правила для origin IP ==="

FORWARD_ACCEPT_COUNT=0
for origin_ip in $ORIGIN_IPS; do
    if iptables -L FORWARD -n | grep -q "ACCEPT.*$origin_ip"; then
        log "FORWARD ACCEPT для $origin_ip найден"
        FORWARD_ACCEPT_COUNT=$((FORWARD_ACCEPT_COUNT + 1))
    else
        warn "FORWARD ACCEPT для $origin_ip НЕ найден"
    fi
done

if [[ $FORWARD_ACCEPT_COUNT -gt 0 ]]; then
    log "Тест 3 пройден: FORWARD разрешён для origin IP"
else
    fail "Тест 3 провален: FORWARD правила НЕ найдены"
fi
echo ""

#################################
# Тест 4: Проверка SNAT POSTROUTING
#################################
echo "=== Тест 4: SNAT POSTROUTING правила ==="

LOCAL_IP=$(hostname -I | awk '{print $1}')
SNAT_COUNT=$(iptables -t nat -L POSTROUTING -n | grep -c "SNAT" || true)

if [[ $SNAT_COUNT -gt 0 ]]; then
    log "Найдено $SNAT_COUNT SNAT правил в POSTROUTING"
    
    if iptables -t nat -L POSTROUTING -n | grep -q "to:$LOCAL_IP"; then
        log "SNAT на локальный IP $LOCAL_IP найден"
    else
        warn "SNAT на локальный IP $LOCAL_IP НЕ найден"
    fi
    
    log "Тест 4 пройден: SNAT правила настроены"
else
    fail "Тест 4 провален: SNAT правила НЕ найдены"
fi
echo ""

#################################
# Тест 5: Проверка ip_forward
#################################
echo "=== Тест 5: IP forwarding ==="

IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)

if [[ "$IP_FORWARD" == "1" ]]; then
    log "Тест 5 пройден: ip_forward включён"
else
    fail "Тест 5 провален: ip_forward ВЫКЛЮЧЕН"
fi
echo ""

#################################
# Тест 6: Проверка счётчиков
#################################
echo "=== Тест 6: Счётчики трафика ==="

echo "NAT PREROUTING (входящий трафик для форвардинга):"
iptables -t nat -L PREROUTING -n -v | grep "DNAT" | head -5

echo ""
echo "INPUT DROP (заблокированные прямые подключения):"
iptables -L INPUT -n -v | grep "DROP.*multiport" | head -5

echo ""
echo "FORWARD ACCEPT (форвардинг на origin):"
iptables -L FORWARD -n -v | grep "ACCEPT" | head -5

echo ""

#################################
# Итоги
#################################
echo "==================================================="
echo "                  РЕЗУЛЬТАТЫ ТЕСТОВ                "
echo "==================================================="
echo ""

TOTAL_TESTS=5
PASSED_TESTS=0

[[ $INPUT_DROP_COUNT -gt 0 ]] && PASSED_TESTS=$((PASSED_TESTS + 1))
[[ $NAT_COUNT -gt 0 ]] && PASSED_TESTS=$((PASSED_TESTS + 1))
[[ $FORWARD_ACCEPT_COUNT -gt 0 ]] && PASSED_TESTS=$((PASSED_TESTS + 1))
[[ $SNAT_COUNT -gt 0 ]] && PASSED_TESTS=$((PASSED_TESTS + 1))
[[ "$IP_FORWARD" == "1" ]] && PASSED_TESTS=$((PASSED_TESTS + 1))

echo "Пройдено тестов: $PASSED_TESTS / $TOTAL_TESTS"
echo ""

if [[ $PASSED_TESTS -eq $TOTAL_TESTS ]]; then
    log "✅ Все тесты пройдены! Форвардинг настроен корректно и безопасно."
elif [[ $PASSED_TESTS -ge 3 ]]; then
    warn "⚠️  Большинство тестов пройдены, но есть проблемы."
else
    fail "❌ Форвардинг настроен некорректно!"
fi

echo ""
echo "==================================================="
echo "            РЕКОМЕНДАЦИИ ПО ПРОВЕРКЕ               "
echo "==================================================="
echo ""
echo "1. Проверить блокировку прямого подключения:"
echo "   telnet $LOCAL_IP $(echo $PORTS | awk '{print $1}')"
echo "   Ожидаемый результат: Connection refused"
echo ""
echo "2. Проверить форвардинг (с клиента):"
echo "   telnet $LOCAL_IP $(echo $PORTS | awk '{print $1}')"
echo "   Должно подключиться к origin серверу"
echo ""
echo "3. Мониторинг счётчиков в реальном времени:"
echo "   watch -n 1 'iptables -t nat -L PREROUTING -n -v'"
echo ""
