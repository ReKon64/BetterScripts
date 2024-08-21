#!/usr/bin/env ruby
require 'nokogiri'
require 'optparse'
require 'open3'
require 'colorize'
require 'concurrent-ruby'

# Set up a global flag for graceful shutdown
$shutdown_requested = false

=begin
TO DO

- Allow for use of state files
- Flag that will clear state files
- Overwrite guard
=end

# ArgParser
options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: script.rb -u <url> -x /path/nmap/xml [options]"

  opts.on('-fVALUE', '--file=VALUE', 'Path to nmap\'s XML to parse') do |value|
    options[:file] = value
  end

  opts.on('-uVALUE', '--url=VALUE', 'Format: http[s]://<ip_or_domainName>/') do |value|
    options[:url] = value
  end

  opts.on('-xVALUE', '--extensions=VALUE', 'Extensions put in " " to pass to ferox') do |value|
    options[:extensions] = value
  end

  opts.on('-h', '--help', 'Displays help') do
    puts opts
    exit
  end
end.parse!

# Flag Validation
if options[:file].nil?
  puts "Error: Nmap XML file is required. Use -f or --file to specify.".red
  exit 1
end

if options[:url].nil?
  puts "Error: URL not supplied. Format: http[s]://<ip_or_domainName>/ "
  exit 1
end

# Prepend "http://" if the URL does include it
unless options[:url].match?(/^https?:\/\//)
  options[:url] = "http://#{options[:url]}"
end

# Open and read the file contents
begin
  xml_data = File.read(options[:file])
rescue Errno::ENOENT
  puts "Error: File not found.".red
  exit 1
rescue Errno::EACCES
  puts "Error: Permission denied.".red
  exit 1
end

# Parse XML
doc = Nokogiri::XML(xml_data)

# Initialize the hash
ports = {}

# Extract and put in hash
doc.xpath('//port').each do |port|
  port_id = port['portid'].to_i  # Convert port_id to an integer
  protocol = port['protocol']

  state_element = port.at_xpath('state')
  state = state_element['state'] if state_element

  service_element = port.at_xpath('service')
  product = service_element['product'] if service_element
  service_name = service_element['name'] if service_element

  # Store in the hash using key: value convention
  ports[port_id] = {
    protocol: protocol,
    state: state || "unknown",  # Default to "unknown" if state is nil
    product: product || "unknown",  # Default to "unknown" if product is nil
    service_name: service_name || "unknown"  # Default to "unknown" if service_name is nil
  }
end

# Set up the thread pool with a timeout mechanism
pool = Concurrent::FixedThreadPool.new(128)

# Setting up a SIGTERM handler for graceful shutdown
Signal.trap("SIGTERM") do
  puts "Received SIGTERM, initiating graceful shutdown...".red
  $shutdown_requested = true
  pool.shutdown
  if !pool.wait_for_termination(10)  # Wait for threads to finish, max 10 seconds
    puts "Forcing shutdown...".red
    pool.kill  # Forcefully terminate the threads if they don't finish in time
  end
  exit 0
end

ports.each do |port, details|
  if details[:service_name] =~ /http/i  # Case-insensitive match for "http"
    pool.post do
      udetails = details[:product].gsub(" ", "_")
      output_filename = "#{port}.#{udetails}.bferox"
      url = options[:url]
      result = url.match(%r{^(https?://[^/]+/)})
      url = result[1].chomp('/') if result
      
      http_ports = ports.select { |_, details| details[:service_name] =~ /http/i }

      nThreads = http_ports.size.zero? ? 1 : (128 / http_ports.size).floor
      #ports.size.zero? ? 1 : (128 / ports.size).floor
      #puts nThreads

      wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"

      # We're gonna use --silent to hide all the garbage and only show STDOUT urls
      File.open(output_filename, 'w') do |file|
        command = "feroxbuster -u #{url}:#{port} --extract-links -x #{options[:extensions]} -B -C 404 -w=#{wordlist} -T 15 -t #{nThreads} -k --force-recursion --silent"
        puts ("Busting #{url}:#{port} using #{wordlist} with #{nThreads} threads").light_cyan

        Open3.popen3(command) do |stdin, stdout, stderr, thread|
          mutex = Mutex.new

          stdout_thread = Thread.new do
            stdout.each_line do |line|
              break if $shutdown_requested  # Stop processing if shutdown is requested
              next if line.strip.empty?

              mutex.synchronize do
                puts (line.strip).green
                file.write(line)
              end
            end
          end

          stderr_thread = Thread.new do
            stderr.each_line do |line|
              break if $shutdown_requested  # Stop processing if shutdown is requested
              # Handle standard error output
              $stderr.print ("ERROR: #{line}").red
            end
          end

          # Wait for all threads to finish
          stdout_thread.join
          stderr_thread.join

          # Wait for the process to complete
          thread.value
        end
      end
    end
  end
end

# Shutdown the thread pool once all tasks are posted
pool.shutdown
pool.wait_for_termination

puts "All tasks completed successfully.".green

=begin
Cool Concept to make this like, --display=value and then http is showed into
  regex search then displayed

ports.each do |port, details|
  if details[:service_name] =~ /http/i  # Case-insensitive match for "http"
    # Print the port and its details
    puts "Port: #{port}"
    puts "  Protocol: #{details[:protocol]}"
    puts "  State: #{details[:state]}"
    puts "  Product: #{details[:product]}"
    puts "  Service Name: #{details[:service_name]}"
    puts "---------------------------"
  end
end
=end