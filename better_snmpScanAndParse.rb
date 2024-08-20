#!/usr/bin/env ruby

=begin

Tomorrow's Plans

4. Print windows(?) usernames next, output to filename.windows_usernames

     Done Section
1. Print NS:EXTEND thingy first, output to filename.extend
2. Print currently running software next, output to filename.running
3. Print installed software next, output to filename.installed
5. Print open ports OID = 1.3.6.1.2.1.6.13.1.3 ,output into filename.ports. Print in format IF:PORT, so values between 1-5:5-6 "."
  TCP-MIB::tcpConnLocalPort.0.0.0.0.8083.0.0.0.0.0 = INTEGER: 8083
  TCP-MIB::tcpConnLocalPort.127.0.0.53.53.0.0.0.0.0 = INTEGER: 53
  TCP-MIB::tcpConnLocalPort.192.168.201.156.53.0.0.0.0.0 = INTEGER: 53
100. Print "Whole Dump provided in filename.all. This is a separate dump that does not run specific MIBs"

=end

require 'optparse'
require 'open3'
require 'colorize'

# Vars
options = {
  version: "2c",
  community: "public",
  ip: nil,
  port: "161"
}

# ArgParser
OptionParser.new do |opts|
  opts.banner = "Usage: script.rb [options]"

  opts.on('-vVALUE', '--version=VALUE', 'Version 1|2c , default 2c') do |value|
    options[:version] = value
  end

  opts.on('-cVALUE', '--community=VALUE', 'Community string to use, default "public"') do |value|
    options[:community] = value
  end

  opts.on('-iVALUE', '--ip=VALUE', 'IP to snmpwalk') do |value|
    options[:ip] = value
  end

  opts.on('-pVALUE', '--port=VALUE', 'Target\'s SNMP Port, default 161') do |value|
    options[:port] = value
  end

  opts.on('-h', '--help', 'Displays help') do
    puts opts
    exit
  end
end.parse!

#Flag Validation
if options[:ip].nil?
  puts "Error: IP address is required. Use -i or --ip to specify."
  exit 1
end

#Is snmp-mibs-downloader installed?
def is_smd()
  Open3.popen3("dpkg -l | grep ^ii | grep snmp-mibs-downloader") do |stdin, stdout, stderr, thread|
    !stdout.read.empty?
  end
end

unless is_smd()
  puts ("snmp-mibs-downloader is not installed. Removing 'nsextend' key from mib_exp.").light_red
  puts ("Installation guide: https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp#enumerating-snmp").light_green
  mib_exp.delete(:nsextend)
end


no_mib = "snmpwalk -v #{options[:version]} -c #{options[:community]} #{options[:ip]}:#{options[:port]}"
# Colon sep only works with software 1.3.6.1.2.1.25.6.3.1.2 mib
mib_exp = {
           running_programs:   ["|CAN BE USEFUL| Running Program\'s name\'s", "1.3.6.1.2.1.25.4.2.1.2"],
           installed_software: ["|USEFUL| Installed Software", "1.3.6.1.2.1.25.6.3.1.2"],
           
           tcp_ports:          ["TCP Ports on All IF\'s", "1.3.6.1.2.1.6.13.1.3"],
           system_processes:   ["System Processes", "1.3.6.1.2.1.25.1.6.0"],
           
           nsextend:           ["|?PASSWORDS?| More readable info", "NET-SNMP-EXTEND-MIB::nsExtendOutputFull"],
           all:                ["Dump of all the things", " "]
          }



mib_exp.each do |key, value_array|
  output_filename = "#{key}.#{options[:ip]}.snmp"

  # Overwrite prompt
  if File.exist?(output_filename)
    print ("File #{output_filename} already exists. Overwrite? (y/N): ").light_red
    user_input = gets.strip.downcase

    unless user_input == 'y'
      puts ("Skipping #{output_filename}").blue
      next
    end
  end

  # Open the file for writing
  File.open(output_filename, 'w') do |file|
    command = "#{no_mib} #{value_array[1]}"
    puts ("=" * 82).yellow
    puts (command).light_cyan
    puts ("#{value_array[0]}").green

    Open3.popen3(command) do |stdin, stdout, stderr, thread|
      #Mutex to sync file access between threads
      mutex = Mutex.new
      stdout_thread = Thread.new do
        stdout.each_line do |line|
          output = nil

          case key
          when :all, :nsextend
            # For key "all", do not modify the output
            output = line
          when :tcp_ports
            # For key "tcp_ports", extract the IP address and port number
            if line.include?('=')
              equals_parts = line.split('=', 2)
              if equals_parts.length > 1
                value_part = equals_parts[1].strip
                if line.include?('.')
                  parts = line.split('.')
                  if parts.length >= 6
                    ip_address = parts[1..4].join('.')
                    port = parts[5]
                    output = "#{ip_address}:#{port}\n"
                  end
                end
              end
            end
          else
            # Default processing for other keys
            if line.count(':') >= 3
              # Print all after 3rd colon
              parts = line.split(':', 4)
              output = parts[3] if parts.length > 3
            else
              # If fewer than 3 ":", print all after =
              if line.include?('=')
                equals_parts = line.split('=', 2)
                output = equals_parts[1] if equals_parts.length > 1
              end
            end
          end

          # Print and write to file
          if output
            mutex.synchronize do
              # Print to console
              print output

              # Write to file
              file.write(output)
            end
          end
        end
      end

      # Optionally, read from stderr in real-time if needed
      stderr_thread = Thread.new do
        stderr.each_line do |line|
          # Handle standard error output
          $stderr.print "ERROR: #{line}"
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
