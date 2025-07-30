#!/bin/bash

if [ -z "$1" ]; then
    echo "Gerador de relatório completo"
    echo "Uso: $0 <arquivo_ou_pasta>"
    echo ""
    echo "Exemplos:"
    echo "  $0 /var/log/apache2/access.log"
    echo "  $0 /var/log/apache2/"
    exit 1
fi

TARGET="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_JSON="security_report_${TIMESTAMP}.json"
REPORT_TEXT="security_report_${TIMESTAMP}.txt"

echo "Gerando relatório completo de segurança..."
echo "Alvo: $TARGET"
echo ""

if [ -d "$TARGET" ]; then
    echo "Analisando todos os .log na pasta $TARGET"
    LOGS=$(find "$TARGET" -name "*.log" -type f)
    
    if [ -z "$LOGS" ]; then
        echo "Nenhum arquivo .log encontrado em $TARGET"
        exit 1
    fi
    
    echo "Arquivos encontrados:"
    echo "$LOGS"
    echo ""
    
    ruby ../log_analyzer.rb -v -f json -o "$REPORT_JSON" $LOGS > "$REPORT_TEXT"
    
elif [ -f "$TARGET" ]; then
    echo "Analisando arquivo: $TARGET"
    ruby ../log_analyzer.rb -v -f json -o "$REPORT_JSON" "$TARGET" > "$REPORT_TEXT"
else
    echo "Alvo não encontrado: $TARGET"
    exit 1
fi

echo ""
echo "Relatórios gerados:"
echo "  📄 Texto: $REPORT_TEXT"
echo "  📊 JSON: $REPORT_JSON"
echo ""
echo "Resumo rápido:"
grep -E "🚨|📊|🎯" "$REPORT_TEXT" | head -10