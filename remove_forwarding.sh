#!/usr/bin/env bash
set -euo pipefail

log() { echo -e "\033[1;32m[INFO]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
die() { echo -e "\033[1;31m[ERROR]\033[0m $1"; exit 1; }

[[ $EUID -eq 0 ]] || die "Запускать нужно от root"

RULES_FILE="/etc/ufw/relay-forwarding.rules"
BEFORE_RULES="/etc/ufw/before.rules"

echo "==================================================="
echo "         УДАЛЕНИЕ RELAY FORWARDING ПРАВИЛ         "
echo "==================================================="
echo ""

# Проверка существования файла правил
if [[ ! -f "$RULES_FILE" ]]; then
    warn "Файл правил не найден: $RULES_FILE"
    exit 0
fi

# Показываем текущие правила
log "Текущие правила форвардинга:"
grep "^# Origin IPs:" "$RULES_FILE" 2>/dev/null || echo "(информация недоступна)"
grep "^# Ports:" "$RULES_FILE" 2>/dev/null || echo "(информация недоступна)"
echo ""

read -p "Удалить правила форвардинга? [y/N]: " confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && die "Отменено пользователем"

# Бэкап before.rules
cp "$BEFORE_RULES" "${BEFORE_RULES}.bak.$(date +%s)"
log "Создан бэкап: ${BEFORE_RULES}.bak.*"

# Удаление include из before.rules
sed -i "\|@include $RULES_FILE|d" "$BEFORE_RULES"
sed -i "/# Include relay forwarding rules/d" "$BEFORE_RULES"
log "Include удалён из before.rules"

# Удаление файла правил
rm -f "$RULES_FILE"
log "Файл правил удалён: $RULES_FILE"

# Перезапуск UFW
log "Перезапуск UFW..."
ufw reload

echo ""
log "Правила форвардинга успешно удалены"
warn "Правила UFW allow остались (удалите вручную через: ufw delete allow PORT/PROTO)"
echo ""
