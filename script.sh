#!/bin/bash

SRC_IP=$1

# Define the table and chain (if they don't already exist)
nft add table inet filter
nft add chain inet filter input { type filter hook input priority 0 \; }
nft add chain inet filter output { type filter hook output priority 0 \; }

# Block all incoming and outgoing connections to the specified IP
nft add rule inet filter input ip saddr $SRC_IP drop
nft add rule inet filter output ip daddr $SRC_IP drop

echo "Blocked all connections to/from $SRC_IP"


