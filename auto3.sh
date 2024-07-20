#!/bin/bash

# Function to send alerts
send_alert() {
    local message=$1
    local ips=("192.168.1.14")
    local ports=(5000 5000)
    
    for i in "${!ips[@]}"; do
        local ip=${ips[$i]}
        local port=${ports[$i]}
        # Create socket and send message
        echo "Sending alert to $ip:$port..."
        echo $message | nc $ip $port
        if [ $? -ne 0 ]; then
            echo "Failed to send alert to $ip:$port"
        fi
    done
}

# Check if auto.sh is running
check_auto_sh_running() {
    if ! pgrep -f "auto.sh" > /dev/null; then
        echo "Malware Detection Model failed to run......"
        send_alert "Alert: auto.sh is not running at $(date)"
    else
        echo "auto.sh is running."
    fi
}

# Check if auto2.sh is running
check_auto2_sh_running() {
    if ! pgrep -f "auto2.sh" > /dev/null; then
        echo "Anomaly Detection Model failed to run......"
        send_alert "Alert: auto2.sh is not running at $(date)"
    else
        echo "auto2.sh is running."
    fi
}

# Main loop to check scripts every 5 minutes
while true; do
    check_auto_sh_running
    check_auto2_sh_running
    sleep 300  # sleep for 5 minutes
done
