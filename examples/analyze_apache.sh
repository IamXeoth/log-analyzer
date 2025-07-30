#!/bin/bash

if [ ! -f "/var/log/apache2/access.log" ]; then
    echo "Apache access log não encontrado."
    echo "Testando com log de exemplo..."
    
    if [ -f "../sample_logs/apache_access.log" ]; then
        ruby ../log_analyzer.rb -v ../sample_logs/apache_access.log
    else
        echo "Sem logs para testar. Coloque um arquivo em sample_logs/"
    fi
else
    echo "Analisando logs do Apache..."
    ruby ../log_analyzer.rb -v /var/log/apache2/access.log
fi

---