#!/usr/bin/env ruby

require 'json'
require 'time'
require 'optparse'
require 'digest'
require 'ipaddr'

class SecurityLogAnalyzer
  # Padrões de ataques conhecidos
  ATTACK_PATTERNS = {
    sql_injection: [
      /select.*from/i,
      /union.*select/i,
      /drop.*table/i,
      /insert.*into/i,
      /delete.*from/i,
      /'.*or.*'.*=/i,
      /1=1/,
      /sleep\(/i,
      /benchmark\(/i
    ],
    xss: [
      /<script.*>/i,
      /javascript:/i,
      /onerror=/i,
      /onload=/i,
      /eval\(/i,
      /alert\(/i,
      /document\.cookie/i
    ],
    lfi: [
      /\.\.\/.*\.\./,
      /\/etc\/passwd/i,
      /\/proc\/self\/environ/i,
      /php:\/\/filter/i,
      /data:\/\/text/i
    ],
    brute_force: [
      /failed.*login/i,
      /authentication.*failed/i,
      /invalid.*password/i,
      /login.*attempt/i,
      /unauthorized.*access/i
    ],
    directory_traversal: [
      /\.\.\/\.\.\//,
      /\.\.\\\.\.\\/, 
      /%2e%2e%2f/i,
      /%252e%252e%252f/i
    ],
    command_injection: [
      /;.*whoami/i,
      /\|.*cat/i,
      /`.*`/,
      /\$\(.*\)/,
      /nc.*-l/i,
      /bash.*-i/i,
      /sh.*-i/i
    ]
  }

  # IPs suspeitos conhecidos (exemplo - em produção usar feeds de threat intelligence)
  SUSPICIOUS_IPS = [
    '192.168.1.100',  # Exemplo de IP interno suspeito
    '10.0.0.50'       # Exemplo
  ]

  def initialize(options = {})
    @log_files = options[:files] || []
    @output_format = options[:format] || :text
    @output_file = options[:output]
    @time_range = options[:time_range]
    @severity_filter = options[:severity]
    @verbose = options[:verbose] || false
    
    @alerts = []
    @statistics = {
      total_entries: 0,
      attacks_detected: 0,
      unique_ips: Set.new,
      attack_types: Hash.new(0),
      hourly_activity: Hash.new(0),
      top_attacked_paths: Hash.new(0)
    }
  end

  def analyze
    puts "🔍 Iniciando análise de logs de segurança..."
    puts "📁 Arquivos: #{@log_files.join(', ')}"
    puts "-" * 60

    @log_files.each do |file|
      analyze_file(file)
    end

    generate_report
    save_report if @output_file
  end

  private

  def analyze_file(file_path)
    puts "📖 Analisando: #{file_path}" if @verbose

    unless File.exist?(file_path)
      puts "❌ Arquivo não encontrado: #{file_path}"
      return
    end

    File.foreach(file_path).with_index do |line, line_num|
      @statistics[:total_entries] += 1
      
      entry = parse_log_entry(line.strip)
      next unless entry && within_time_range?(entry[:timestamp])

      @statistics[:unique_ips].add(entry[:ip]) if entry[:ip]
      update_hourly_stats(entry[:timestamp])
      
      # Detecta ataques
      detected_attacks = detect_attacks(entry)
      
      detected_attacks.each do |attack|
        @statistics[:attacks_detected] += 1
        @statistics[:attack_types][attack[:type]] += 1
        @statistics[:top_attacked_paths][entry[:path]] += 1 if entry[:path]
        
        alert = create_alert(entry, attack, file_path, line_num + 1)
        @alerts << alert
        
        puts "🚨 #{alert[:severity]} - #{attack[:type]}: #{entry[:ip]}" if @verbose
      end

      # Detecta IPs suspeitos
      if suspicious_ip?(entry[:ip])
        alert = {
          timestamp: entry[:timestamp],
          severity: 'MEDIUM',
          type: 'suspicious_ip',
          description: "Acesso de IP suspeito: #{entry[:ip]}",
          source_ip: entry[:ip],
          raw_log: line.strip,
          file: file_path,
          line: line_num + 1
        }
        @alerts << alert
      end

      # Detecta atividade anômala (muitas requisições do mesmo IP)
      detect_anomalous_activity(entry)
    end
  end

  def parse_log_entry(line)
    # Tenta vários formatos de log
    
    # Apache/Nginx Combined Log Format
    if match = line.match(/^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) \S+ "(.*?)" "(.*?)"/)
      return {
        ip: match[1],
        timestamp: parse_timestamp(match[2]),
        request: match[3],
        status: match[4].to_i,
        referrer: match[5],
        user_agent: match[6],
        path: extract_path(match[3]),
        method: extract_method(match[3]),
        raw: line
      }
    end

    # Apache Error Log
    if match = line.match(/^\[(.*?)\] \[(\w+)\] \[client ([\d\.]+).*?\] (.*)/)
      return {
        timestamp: parse_timestamp(match[1]),
        level: match[2],
        ip: match[3],
        message: match[4],
        raw: line
      }
    end

    # Syslog format
    if match = line.match(/^(\w+\s+\d+\s+\d+:\d+:\d+) (\S+) (\S+): (.*)/)
      return {
        timestamp: parse_timestamp(match[1]),
        host: match[2],
        process: match[3],
        message: match[4],
        raw: line
      }
    end

    # JSON format
    begin
      json_entry = JSON.parse(line)
      return {
        timestamp: parse_timestamp(json_entry['timestamp'] || json_entry['@timestamp']),
        ip: json_entry['remote_addr'] || json_entry['client_ip'],
        request: json_entry['request'],
        status: json_entry['status'],
        path: json_entry['request_uri'] || extract_path(json_entry['request']),
        method: json_entry['request_method'] || extract_method(json_entry['request']),
        user_agent: json_entry['http_user_agent'],
        raw: line
      }
    rescue JSON::ParserError
      # Não é JSON, continua
    end

    # Formato genérico - tenta extrair IP pelo menos
    if match = line.match(/((?:\d{1,3}\.){3}\d{1,3})/)
      return {
        ip: match[1],
        timestamp: Time.now, # Fallback
        message: line,
        raw: line
      }
    end

    nil
  end

  def detect_attacks(entry)
    attacks = []
    content = "#{entry[:request]} #{entry[:path]} #{entry[:message]}".to_s.downcase

    ATTACK_PATTERNS.each do |attack_type, patterns|
      patterns.each do |pattern|
        if content.match?(pattern)
          severity = calculate_severity(attack_type, entry)
          
          attacks << {
            type: attack_type,
            pattern: pattern.source,
            severity: severity,
            confidence: calculate_confidence(pattern, content)
          }
          break # Evita múltiplas detecções do mesmo tipo
        end
      end
    end

    attacks
  end

  def detect_anomalous_activity(entry)
    return unless entry[:ip]

    @ip_activity ||= Hash.new { |h, k| h[k] = [] }
    @ip_activity[entry[:ip]] << entry[:timestamp]

    # Remove entradas antigas (última hora)
    cutoff_time = Time.now - 3600
    @ip_activity[entry[:ip]].reject! { |time| time < cutoff_time }

    # Detecta rate limiting
    if @ip_activity[entry[:ip]].size > 100 # 100 requests na última hora
      alert = {
        timestamp: entry[:timestamp],
        severity: 'HIGH',
        type: 'rate_limiting',
        description: "Taxa anômala de requisições de #{entry[:ip]}: #{@ip_activity[entry[:ip]].size} requests/hora",
        source_ip: entry[:ip],
        raw_log: entry[:raw]
      }
      @alerts << alert
    end
  end

  def suspicious_ip?(ip)
    return false unless ip
    
    begin
      ip_obj = IPAddr.new(ip)
      
      # Verifica lista de IPs suspeitos
      return true if SUSPICIOUS_IPS.include?(ip)
      
      # Verifica ranges privados sendo acessados externamente (exemplo)
      private_ranges = [
        IPAddr.new('10.0.0.0/8'),
        IPAddr.new('172.16.0.0/12'),
        IPAddr.new('192.168.0.0/16')
      ]
      
      # Se o IP não é privado mas está tentando acessar recursos que parecem internos
      if !private_ranges.any? { |range| range.include?(ip_obj) }
        # Adicione lógica específica aqui
      end
      
      false
    rescue IPAddr::InvalidAddressError
      false
    end
  end

  def calculate_severity(attack_type, entry)
    case attack_type
    when :sql_injection, :command_injection
      'CRITICAL'
    when :xss, :lfi
      'HIGH'
    when :brute_force, :directory_traversal
      entry[:status] == 200 ? 'HIGH' : 'MEDIUM'
    else
      'MEDIUM'
    end
  end

  def calculate_confidence(pattern, content)
    # Confiança baseada na especificidade do padrão
    pattern_complexity = pattern.source.length
    matches = content.scan(pattern).length
    
    base_confidence = [pattern_complexity * 2, 100].min
    bonus = matches > 1 ? 20 : 0
    
    [base_confidence + bonus, 100].min
  end

  def create_alert(entry, attack, file, line_num)
    {
      timestamp: entry[:timestamp],
      severity: attack[:severity],
      type: attack[:type],
      description: "Possível #{attack[:type].to_s.tr('_', ' ')} detectado",
      source_ip: entry[:ip],
      target_path: entry[:path],
      pattern_matched: attack[:pattern],
      confidence: attack[:confidence],
      raw_log: entry[:raw],
      file: file,
      line: line_num,
      additional_context: {
        user_agent: entry[:user_agent],
        referrer: entry[:referrer],
        status_code: entry[:status],
        method: entry[:method]
      }
    }
  end

  def generate_report
    puts "\n" + "=" * 80
    puts "🛡️  RELATÓRIO DE ANÁLISE DE SEGURANÇA"
    puts "=" * 80
    puts "📊 Total de entradas analisadas: #{@statistics[:total_entries]}"
    puts "🚨 Ataques detectados: #{@statistics[:attacks_detected]}"
    puts "🌐 IPs únicos: #{@statistics[:unique_ips].size}"
    puts "⏰ Período analisado: #{@time_range || 'Todos os registros'}"
    puts

    if @alerts.empty?
      puts "✅ Nenhum ataque detectado nos logs analisados"
      return
    end

    # Top 10 alertas por severidade
    puts "🔴 ALERTAS POR SEVERIDADE:"
    severity_counts = @alerts.group_by { |a| a[:severity] }
    %w[CRITICAL HIGH MEDIUM LOW].each do |severity|
      count = severity_counts[severity]&.size || 0
      puts "   #{severity}: #{count}" if count > 0
    end
    puts

    # Top tipos de ataque
    puts "⚔️  TOP TIPOS DE ATAQUE:"
    @statistics[:attack_types].sort_by { |_, count| -count }.first(5).each do |type, count|
      puts "   #{type.to_s.tr('_', ' ').capitalize}: #{count}"
    end
    puts

    # Top IPs atacantes
    puts "🎯 TOP IPs ATACANTES:"
    ip_counts = @alerts.group_by { |a| a[:source_ip] }.transform_values(&:size)
    ip_counts.sort_by { |_, count| -count }.first(10).each do |ip, count|
      puts "   #{ip}: #{count} ataques"
    end
    puts

    # Atividade por hora
    puts "⏰ ATIVIDADE POR HORA:"
    @statistics[:hourly_activity].sort.each do |hour, count|
      puts "   #{hour}:00 - #{count} eventos"
    end
    puts

    # Alertas críticos recentes
    critical_alerts = @alerts.select { |a| a[:severity] == 'CRITICAL' }.last(5)
    if critical_alerts.any?
      puts "🚨 ALERTAS CRÍTICOS RECENTES:"
      critical_alerts.each do |alert|
        puts "   [#{alert[:timestamp]}] #{alert[:type]} de #{alert[:source_ip]}"
        puts "      #{alert[:description]}"
        puts "      Arquivo: #{alert[:file]}:#{alert[:line]}"
        puts
      end
    end
  end

  def save_report
    report = {
      analysis_date: Time.now.iso8601,
      statistics: @statistics.merge(unique_ips: @statistics[:unique_ips].to_a),
      alerts: @alerts,
      summary: {
        total_alerts: @alerts.size,
        critical_alerts: @alerts.count { |a| a[:severity] == 'CRITICAL' },
        high_alerts: @alerts.count { |a| a[:severity] == 'HIGH' },
        medium_alerts: @alerts.count { |a| a[:severity] == 'MEDIUM' }
      }
    }

    case @output_format
    when :json
      File.write(@output_file, JSON.pretty_generate(report))
    when :csv
      generate_csv_report(report)
    else
      File.write(@output_file, format_text_report(report))
    end

    puts "💾 Relatório salvo em: #{@output_file}"
  end

  # Métodos auxiliares
  def parse_timestamp(timestamp_str)
    return Time.now unless timestamp_str

    formats = [
      '%d/%b/%Y:%H:%M:%S %z',  # Apache
      '%Y-%m-%d %H:%M:%S',     # MySQL/PostgreSQL
      '%b %d %H:%M:%S',        # Syslog
      '%Y-%m-%dT%H:%M:%S'      # ISO 8601
    ]

    formats.each do |format|
      begin
        return Time.strptime(timestamp_str, format)
      rescue ArgumentError
        next
      end
    end

    # Tenta parsing automático
    begin
      Time.parse(timestamp_str)
    rescue ArgumentError
      Time.now
    end
  end

  def extract_path(request)
    return nil unless request
    request.split(' ')[1] # GET /path HTTP/1.1
  end

  def extract_method(request)
    return nil unless request
    request.split(' ')[0] # GET /path HTTP/1.1
  end

  def within_time_range?(timestamp)
    return true unless @time_range
    # Implementar lógica de range de tempo se necessário
    true
  end

  def update_hourly_stats(timestamp)
    return unless timestamp
    hour = timestamp.hour
    @statistics[:hourly_activity][hour] += 1
  end
end

# CLI Interface
if __FILE__ == $0
  options = {}
  
  OptionParser.new do |opts|
    opts.banner = "Uso: #{$0} [opções] arquivo1.log [arquivo2.log ...]"
    
    opts.on("-f", "--format FORMAT", "Formato de saída: text, json, csv") do |format|
      options[:format] = format.to_sym
    end
    
    opts.on("-o", "--output FILE", "Arquivo de saída") do |file|
      options[:output] = file
    end
    
    opts.on("-v", "--verbose", "Modo verboso") do
      options[:verbose] = true
    end
    
    opts.on("-s", "--severity LEVEL", "Filtrar por severidade: CRITICAL, HIGH, MEDIUM, LOW") do |severity|
      options[:severity] = severity.upcase
    end
    
    opts.on("-h", "--help", "Mostra esta ajuda") do
      puts opts
      exit
    end
  end.parse!

  if ARGV.empty?
    puts "❌ Erro: especifique pelo menos um arquivo de log"
    puts "Exemplo: #{$0} -v -f json -o relatorio.json /var/log/apache2/access.log"
    exit 1
  end

  options[:files] = ARGV
  
  analyzer = SecurityLogAnalyzer.new(options)
  analyzer.analyze
end
