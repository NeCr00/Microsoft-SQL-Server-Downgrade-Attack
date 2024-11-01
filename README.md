# MSSQL TDS Downgrade Attack 

This repository contains code and scripts for performing a downgrade attack on Microsoft SQL Server's native authentication. The attack exploits the default configuration of MSSQL, where login credentials are submitted encrypted via TLS/SSL. By manipulating the network traffic, an attacker can trick the client/server into believing that encryption is not supported, resulting in the submission of credentials in plaintext.

A walkthrough of the attack and more details can be found here: <link>

## Instructions

1. **Create the module directory and start Metasploit to load the module**

   ```bash
    #Create the directory and copy the exploit
    mkdir ./modules/exploits
    cp MSSQL_Downgrade_Attack.rb ./modules/exploits
    
    #Start msfconsole with root privileges and load the module path
    sudo msfconsole
    loadpath <full_path>/modules/exploits
    
    #Reload all the modules to include the new imported module
    reload_all
    
    #Search and find the exploit
    search MSSQL_Downgrade_Attack
    ```

3. **Set the necessary parameters for the module, such as target IP addresses, ports, and any other required fields. To view the available options, type**

    ```bash
    msf6 > show options
    
    #Then, fill in each required parameter:
    msf6 > set <parameter_name> <value>
    ```
    
5. **After configuring the parameters, execute the module**

     
6. **Once the module is running, initiate a connection attempt from the client side. This will trigger a login attempt in order to capture the MSSQL account credentials.**
 


## Disclaimer

This repository and its contents are provided for educational and research purposes only. The code and scripts should be used responsibly and with proper authorization. The author and repository contributors are not responsible for any misuse or damages caused by the utilization of the provided materials.

