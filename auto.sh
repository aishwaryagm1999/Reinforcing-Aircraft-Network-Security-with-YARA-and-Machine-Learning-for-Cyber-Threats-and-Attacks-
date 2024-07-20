#!/bin/bash

# Infinite loop to run the Python script every 5 minutes
while true; do
    echo "Running rulematch2.py..."
    python3 rulematch2.py
    echo "Finished running rulematch2.py at $(date)"
    # Wait for 5 minutes before running the script again
    sleep 300
done