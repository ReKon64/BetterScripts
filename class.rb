#!/usr/bin/env ruby
require 'nokogiri'

class NmapXMLParser
  def initialize(path)
    raise "Path can't be nil" if path.nil?

    @path = path
    @hosts = {}  # Initialize @hosts as an instance variable to accumulate data
    is_accessible?
  end

  def is_accessible? # Needs to be called. Otherwise doesn't give data to nokogiri later in "parse"
    begin
      @xml_data = File.read(@path)
      true
    rescue Errno::ENOENT
      puts "Error: File not found.".red
      false
    rescue Errno::EACCES
      puts "Error: Permission denied.".red
      false
    end
  end

  def parse
    nDoc = Nokogiri::XML(@xml_data)

    # Iterate over each 'host' element in the XML
    nDoc.xpath('//host').each do |host|
      # Extract the host address
      address_element = host.at_xpath('address')
      host_address = address_element['addr'] if address_element
      
      # Initialize a new hash for the ports associated with this host
      host_ports = {}

      # Iterate over each 'port' element within the current host
      host.xpath('ports/port').each do |port|
        port_id = port['portid'].to_i
        protocol = port['protocol']

        state_element = port.at_xpath('state')
        state = state_element['state'] if state_element

        service_element = port.at_xpath('service')
        product = service_element['product'] if service_element
        service_name = service_element['name'] if service_element

        # Store port data in the host_ports hash
        host_ports[port_id] = {
          protocol: protocol,
          state: state || "unknown",  # Default to "unknown" if state is nil
          product: product || "unknown",  # Default to "unknown" if product is nil
          service_name: service_name || "unknown"  # Default to "unknown" if service_name is nil
        }
      end

      # Append or merge new host and port data into @hosts
      if @hosts[host_address]
        # If the host already exists, merge the new ports into the existing entry
        @hosts[host_address][:ports].merge!(host_ports)
      else
        # Otherwise, add the new host and its ports
        @hosts[host_address] = {
          ports: host_ports
        }
      end
    end

    # Debug print to check @hosts after parsing
    puts "Parsed Hosts: #{@hosts.inspect}"
  end

  def debug_hosts_get
    puts "Hosts Data: #{@hosts.inspect}"  # Debug output to check @hosts data
  end
end

parser = NmapXMLParser.new("/home/rekon/Downloads/sampleNMAPXMLUniminified.xml")
parser.parse


=begin
nmapData = nmapXMLParser.new("/path/nmap.xml")
nmapData.getFTP
  output FTP ports
nmapData.getHTTP
  output HTTP ports

    for object in xml do:
      port.at_xpath('object')&.then do |object_element|
      {
        object: service_element['product'],
        name: service_element['name'],
      }

=end