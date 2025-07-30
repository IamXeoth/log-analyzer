# Security Log Analyzer

Analisador de logs de segurança que detecta ataques automaticamente. Funciona com Apache, Nginx, e outros formatos comuns.

## O que detecta

- **SQL Injection** - tentativas de injeção SQL
- **XSS** - cross-site scripting 
- **LFI** - local file inclusion
- **Brute Force** - ataques de força bruta
- **Directory Traversal** - tentativas de navegar em diretórios
- **Command Injection** - injeção de comandos
- **IPs suspeitos** - baseado em listas conhecidas
- **Rate limiting** - muitas requests do mesmo IP

## Como usar

Análise básica:
```bash
ruby log_analyzer.rb /var/log/apache2/access.log
```

Com mais detalhes:
```bash
ruby log_analyzer.rb -v /var/log/nginx/access.log
```

Salvar relatório em JSON:
```bash
ruby log_analyzer.rb -f json -o relatorio.json /var/log/apache2/access.log
```

Analisar vários arquivos:
```bash
ruby log_analyzer.rb -v /var/log/apache2/access.log /var/log/nginx/access.log
```

## Opções

- `-f` - formato de saída: text, json, csv
- `-o` - arquivo para salvar o relatório
- `-v` - modo verboso (mostra mais detalhes)
- `-s` - filtrar por severidade: CRITICAL, HIGH, MEDIUM, LOW

## Formatos suportados

- Apache access/error logs
- Nginx access/error logs  
- JSON logs
- Syslog
- Formato genérico (tenta extrair IPs pelo menos)

## Exemplo do que aparece

```
🔍 Iniciando análise de logs de segurança...
📁 Arquivos: /var/log/apache2/access.log
------------------------------------------------------------
📖 Analisando: /var/log/apache2/access.log
🚨 MEDIUM - sql_injection: 192.168.1.100
🚨 HIGH - xss: 10.0.0.50

================================================================================
🛡️  RELATÓRIO DE ANÁLISE DE SEGURANÇA
================================================================================
📊 Total de entradas analisadas: 15420
🚨 Ataques detectados: 23
🌐 IPs únicos: 892

🔴 ALERTAS POR SEVERIDADE:
   CRITICAL: 2
   HIGH: 8
   MEDIUM: 13

⚔️  TOP TIPOS DE ATAQUE:
   Sql injection: 8
   Xss: 6
   Brute force: 9

🎯 TOP IPs ATACANTES:
   192.168.1.100: 5 ataques
   10.0.0.50: 3 ataques
```

## Aviso

Só analise logs que você tem permissão para acessar. Óbvio, né?

OS LOGS SÃO EXEMPLOS!!!

## Requisitos

Ruby 2.7+
