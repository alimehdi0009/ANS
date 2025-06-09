#for mininet server ser-4100

addresses="10.1.0.3 10.1.1.3 10.3.1.3"

mkdir -p "ft"

# Output file
output_file="./ft/ft_routing_ping_102.txt"

if [ -f "$output_file" ]; then
    rm "$output_file"
fi

# Loop through IPs
for ip in $addresses; do
    echo "10.1.0.2 Pinging $ip" | tee -a $output_file
    ping -c 5 $ip >> $output_file
    echo "=====================================================" >> $output_file
done
