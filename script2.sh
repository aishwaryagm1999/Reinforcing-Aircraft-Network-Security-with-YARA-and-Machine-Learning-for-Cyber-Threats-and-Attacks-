#!/bin/bash

# Interfaces to limit bandwidth
IFACES=("enp0s3" "enp0s8")
# Bandwidth limit (adjust as necessary)
LIMIT="20kbit"

# Apply limit to each interface
for IFACE in "${IFACES[@]}"; do
    # Clear existing rules
    tc qdisc del dev $IFACE root 2>/dev/null

    # Apply new bandwidth limit
    tc qdisc add dev $IFACE root handle 1: htb default 11
    tc class add dev $IFACE parent 1: classid 1:1 htb rate $LIMIT
    tc class add dev $IFACE parent 1:1 classid 1:11 htb rate $LIMIT

    echo "Applied $LIMIT bandwidth limit on $IFACE."
done
