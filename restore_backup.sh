#!/usr/bin/env bash
set -euo pipefail

log() { echo -e "\033[1;32m[INFO]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
die() { echo -e "\033[1;31m[ERROR]\033[0m $1"; exit 1; }

[[ $EUID -eq 0 ]] || die "Запускать нужно от root"

BEFORE_RULES="/etc/ufw/before.rules"

echo "==================================================="
echo "       ВОССТАНОВЛЕНИЕ ИЗ БЭКАПА before.rules      "
echo "==================================================="
echo ""

# Поиск бэкапов
BACKUPS=$(ls -t "${BEFORE_RULES}.bak."* 2>/dev/null | head -10 || true)

if [[ -z "$BACKUPS" ]]; then
    die "Бэкапы не найдены: ${BEFORE_RULES}.bak.*"
fi

# Показать доступные бэкапы
echo "Доступные бэкапы (от новых к старым):"
echo ""

i=1
while IFS= read -r backup; do
    timestamp=$(basename "$backup" | cut -d. -f4)
    if [[ "$timestamp" =~ ^[0-9]+$ ]]; then
        date_str=$(date -d "@$timestamp" 2>/dev/null || echo "неизвестно")
    else
        date_str="$timestamp"
    fi
    
    size=$(du -h "$backup" | cut -f1)
    
    echo "[$i] $backup"
    echo "    Дата: $date_str"
    echo "    Размер: $size"
    echo ""
    
    i=$((i + 1))
done <<< "$BACKUPS"

echo ""
read -p "Выберите номер бэкапа для восстановления [1-$((i-1))]: " choice

# Проверка ввода
if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 ]] || [[ "$choice" -ge $i ]]; then
    die "Невалидный выбор"
fi

# Получить выбранный бэкап
selected_backup=$(echo "$BACKUPS" | sed -n "${choice}p")

echo ""
warn "Восстановление из: $selected_backup"
warn "Текущий before.rules будет перезаписан!"
echo ""
read -p "Продолжить? [y/N]: " confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && die "Отменено пользователем"

# Создать бэкап текущего перед восстановлением
cp "$BEFORE_RULES" "${BEFORE_RULES}.before-restore.$(date +%s)"
log "Создан бэкап текущего: ${BEFORE_RULES}.before-restore.*"

# Восстановление
cp "$selected_backup" "$BEFORE_RULES"
log "Восстановлено из бэкапа: $selected_backup"

# Перезапуск UFW
log "Перезапуск UFW..."
if ufw reload; then
    echo ""
    log "✅ Восстановление успешно завершено"
else
    warn "❌ Ошибка при перезапуске UFW"
    warn "Восстановите вручную из: ${BEFORE_RULES}.before-restore.*"
fi

echo ""
