#!/bin/bash

if [ -z "$1" ]; then
    echo "Monitor contínuo de log"
    echo "Uso: $0 <arquivo.log>"
    echo "Exemplo: $0 /var/log/apache2/access.log"
    echo ""
    echo "Vai ficar monitorando e mostrando novos ataques"
    exit 1
fi

LOG_FILE="$1"

if [ ! -f "$LOG_FILE" ]; then
    echo "Arquivo não encontrado: $LOG_FILE"
    exit 1
fi

echo "Monitorando: $LOG_FILE"
echo "Pressione Ctrl+C para parar"
echo "Só vai mostrar ataques detectados..."
echo ""

# Monitora o arquivo e analisa novas linhas
tail -f "$LOG_FILE" | while read line; do
    echo "$line" | ruby ../log_analyzer.rb -v /dev/stdin 2>/dev/null | grep "🚨"
done

---
