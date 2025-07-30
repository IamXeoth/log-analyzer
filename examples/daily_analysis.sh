#!/bin/bash

LOG_DIR="/var/log"
DATE=$(date +"%Y%m%d")
REPORT_FILE="security_analysis_${DATE}.json"

echo "Análise diária de segurança - $(date)"
echo "Relatório será salvo em: $REPORT_FILE"
echo ""

# Lista de logs comuns para analisar
LOGS=(
    "$LOG_DIR/apache2/access.log"
    "$LOG_DIR/nginx/access.log" 
    "$LOG_DIR/auth.log"
    "$LOG_DIR/syslog"
)

EXISTING_LOGS=()

# Verifica quais logs existem
for log in "${LOGS[@]}"; do
    if [ -f "$log" ]; then
        EXISTING_LOGS+=("$log")
        echo "✓ Encontrado: $log"
    fi
done

if [ ${#EXISTING_LOGS[@]} -eq 0 ]; then
    echo "Nenhum log encontrado. Usando logs de exemplo..."
    ruby ../log_analyzer.rb -v -f json -o "$REPORT_FILE" ../sample_logs/*.log
else
    echo ""
    echo "Analisando ${#EXISTING_LOGS[@]} arquivos de log..."
    ruby ../log_analyzer.rb -v -f json -o "$REPORT_FILE" "${EXISTING_LOGS[@]}"
fi

echo ""
echo "Análise completa! Verifique $REPORT_FILE"

---