if [ ! -f "/var/log/nginx/access.log" ]; then
    echo "Nginx access log não encontrado."
    echo "Tentando log de exemplo..."
    
    if [ -f "../sample_logs/nginx_access.log" ]; then
        ruby ../log_analyzer.rb -v ../sample_logs/nginx_access.log
    else
        echo "Sem logs para testar."
    fi
else
    echo "Analisando logs do Nginx..."
    ruby ../log_analyzer.rb -v /var/log/nginx/access.log
fi

---