#!/bin/bash

if [ -z "$1" ]; then
    echo "Análise rápida de um arquivo de log"
    echo "Uso: $0 <arquivo.log>"
    echo "Exemplo: $0 /var/log/apache2/access.log"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo "Arquivo não encontrado: $1"
    exit 1
fi

echo "Análise rápida de: $1"
echo "Só vai mostrar ataques HIGH e CRITICAL..."
echo ""

ruby ../log_analyzer.rb -s HIGH "$1"

---