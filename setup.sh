#!/bin/bash

CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt-get install -y python3 build-essential python3-dev libnetfilter-queue-dev python3-pip net-tools tmux libnfnetlink-dev libnetfilter-queue-dev python3-netaddr
sudo pip3 install -r $CURRENT_DIR/requirements.txt
sudo pip3 install --upgrade service_identity
cd /usr/lib/x86_64-linux-gnu/
sudo ln -s -f libc.a liblibc.a
cd $CURRENT_DIR

# Create a Service to Start Faitour on Reboot
sudo bash -c "cat > /lib/systemd/system/faitour.service" <<EOF
[Unit]
Description=Faitour OS Emulation Tool
After=multi-user.target

[Service]
User=root
WorkingDirectory=$CURRENT_DIR
Type=simple
RemainAfterExit=yes
ExecStart=/usr/bin/python3 $CURRENT_DIR/app.py

[Install]
WantedBy=multi-user.target
EOF

# Enable the Service
sudo systemctl daemon-reload
sudo systemctl enable faitour.service

# That should be it!
printf "\n\nSetup is complete! To finalize the installation:\n"
printf "  * Update the configuration in /opt/Faitour/configuration/host_config.ini\n"
printf "    - IMPORTANT! The 'ip' and 'interface' fields must match your host's setup, or spoofing will not work!"
printf "    - Samples configs may be found in /opt/Faitour/configuration/sample_configs\n"
printf "  * Start the service\n"
printf "    - sudo systemctl start faitour.service\n"
printf "  * Confirm Faitour is working by performing an NMAP scan from another device\n\n"
