#!/bin/bash

# Enable SSH if not already enabled
if [ ! -f /boot/ssh ]; then
    touch /boot/ssh
fi

# Configure display settings for HDMI output (adjust as needed for your setup)
if ! grep -q "hdmi_force_hotplug" /boot/config.txt; then
    echo "hdmi_force_hotplug=1" >> /boot/config.txt
    echo "hdmi_group=2" >> /boot/config.txt
    echo "hdmi_mode=82" >> /boot/config.txt  # 1920x1080 60Hz
fi

# Run the main Python script (adjust path as needed)
python3 /home/pi/main_agent.py &

# Run the IP display server on port 3333
python3 /home/pi/ip_server.py &