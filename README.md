# MSSQL Downgrade Attack Repository

This repository contains code and scripts for performing a downgrade attack on Microsoft SQL Server's native authentication. The attack exploits the default configuration of MSSQL, where login credentials are submitted encrypted via TLS/SSL. By manipulating the network traffic, an attacker can trick the client/server into believing that encryption is not supported, resulting in the submission of credentials in plaintext.

## Files

- **MSSQL_Downgrade_Attack.rb**: Metasploit module for executing the downgrade attack.
- **MitM_Preparation.sh**: Shell script for setting up the environment to perform the Man-in-the-Middle (MITM) attack.

## Prerequisites

Before executing the attack, ensure that you have the following:

1. Root privileges on the system.
2. Knowledge of the network interface name.
3. IPv4 addresses of the MSSQL server and client.
4. MSSQL server port number.

## Instructions

Follow the steps below to perform the downgrade attack:

1. Open a terminal and navigate to the directory containing the repository files.
    
2. Run the `MitM_Preparation.sh` script:
```shell
sudo bash MitM_Preparation.sh
```

This script sets up the firewall rules and performs ARP spoofing for the MITM attack. You will be prompted to provide the following information:

- Network interface: Enter the name of the network interface (e.g., eth0).
- MSSQL server IPv4 address: Enter the IP address of the MSSQL server.
- MSSQL client IPv4 address: Enter the IP address of the MSSQL client.
- MSSQL server port: Enter the port number used by the MSSQL server.
- Once the MITM setup is complete, open a new terminal window and navigate to the directory containing the repository files.
    
- Run the `MSSQL_Downgrade_Attack.rb` script:
```shell
 msfconsole -r MSSQL_Downgrade_Attack.rb
```    

 This will launch the Metasploit framework and execute the downgrade attack.   
 


## Disclaimer

This repository and its contents are provided for educational and research purposes only. The code and scripts should be used responsibly and with proper authorization. The author and repository contributors are not responsible for any misuse or damages caused by the utilization of the provided materials.

## References

- [Microsoft SQL Server Downgrade Attack](http://f0rki.at/microsoft-sql-server-downgrade-attack.html)
- [MSDN - Tabular Data Stream Protocol](http://msdn.microsoft.com/en-us/library/dd304523%28v=PROT.13%29.aspx)
