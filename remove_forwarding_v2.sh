#!/usr/bin/env bash
set -euo pipefail

log() { echo -e "\033[1;32m[INFO]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
die() { echo -e "\033[1;31m[ERROR]\033[0m $1"; exit 1; }

[[ $EUID -eq 0 ]] || die "Запускать нужно от root"

BEFORE_RULES="/etc/ufw/before.rules"
MARKER_START="# === RELAY FORWARDING START ==="
MARKER_END="# === RELAY FORWARDING END ==="

echo "==================================================="
echo "         УДАЛЕНИЕ RELAY FORWARDING ПРАВИЛ         "
echo "==================================================="
echo ""

# Проверка существования маркеров
if ! grep -q "$MARKER_START" "$BEFORE_RULES"; then
    warn "Правила форвардинга не найдены в $BEFORE_RULES"
    exit 0
fi

# Показываем текущие правила
log "Текущие правила форвардинга:"
sed -n "/$MARKER_START/,/$MARKER_END/p" "$BEFORE_RULES" | grep "^# Origin IPs:" || echo "(информация недоступна)"
sed -n "/$MARKER_START/,/$MARKER_END/p" "$BEFORE_RULES" | grep "^# Ports:" || echo "(информация недоступна)"
echo ""

read -p "Удалить правила форвардинга? [y/N]: " confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && die "Отменено пользователем"

# Бэкап before.rules
cp "$BEFORE_RULES" "${BEFORE_RULES}.bak.$(date +%s)"
log "Создан бэкап: ${BEFORE_RULES}.bak.*"

# Удаление правил между маркерами (все вхождения)
sed -i "/$MARKER_START/,/$MARKER_END/d" "$BEFORE_RULES"
log "Правила удалены из before.rules"

# Перезапуск UFW
log "Перезапуск UFW..."
ufw reload

echo ""
log "Правила форвардинга успешно удалены"
warn "Правила UFW allow НЕ удалены (они и не создавались для безопасности)"
echo ""
