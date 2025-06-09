
#for mininet server ser-4200

addresses="10.2.0.3 10.2.1.3 10.3.1.3"

mkdir -p "sp"

# Output file
output_file="./sp/sp_routing_ping_202.txt"

if [ -f "$output_file" ]; then
    rm "$output_file"
fi

# Loop through IPs
for ip in $addresses; do
    echo "10.2.0.2 Pinging $ip" | tee -a $output_file
    ping -c 5 $ip >> $output_file
    echo "=====================================================" >> $output_file
done
