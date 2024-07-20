
#!/bin/bash

while true; do
    # Step 1: Capture network traffic on enp0s8 for 1 minute and save it to testing.pcap
    echo "Starting network capture on enp0s8 for 1 minute..."
    tshark -i enp0s8 -w testing.pcap & PID=$!
    sleep 60
    kill $PID
    echo "Capture complete."

    # Step 2: Process the captured traffic with argus and ra to generate CSV files
    echo "Processing captured traffic..."
    sudo argus -r testing.pcap -w testing.argus

    sudo ra -r testing.argus -s dur,proto,state,spkts,dpkts,sbytes,rate,sttl,dttl,sload,dload,swin,dwin,stcpb,dtcpb,tcprtt | awk 'BEGIN {OFS=","} {print $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17}' > test.csv

    sudo ra -r testing.argus -s saddr,daddr,sport,dport | awk 'BEGIN {OFS=","} {print $1, $2, $3, $4}' > test3.csv

    echo "Processing complete."

    # Step 3: Execute the Python script test2.py
    echo "Executing test2.py..."
    python3 test2.py
    echo "Script execution complete."

    # Wait for 5 minutes before repeating the loop
    sleep 300
done
