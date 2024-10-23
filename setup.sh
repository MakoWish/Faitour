#!/bin/bash


#===============================================================================
# Install requisites
#===============================================================================
printf 'Installing Faitour prerequisites... '
CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
sudo add-apt-repository -y ppa:deadsnakes/ppa &> /dev/null
sudo apt update &> /dev/null
sudo apt-get install -y python3 build-essential python3-dev libnetfilter-queue-dev python3-pip net-tools tmux libnfnetlink-dev libnetfilter-queue-dev python3-netaddr &> /dev/null
sudo pip3 install -r $CURRENT_DIR/requirements.txt &> /dev/null
sudo pip3 install --upgrade service_identity &> /dev/null
cd /usr/lib/x86_64-linux-gnu/
sudo ln -s -f libc.a liblibc.a
cd $CURRENT_DIR
echo 'done.'


#===============================================================================
# Create a Service to Start Faitour on Reboot
#===============================================================================
printf 'Create systemd service file for Faitour to start at boot... '
sudo bash -c "cat > /usr/lib/systemd/system/faitour.service" <<EOF
[Unit]
Description=Faitour OS Emulation Tool
After=multi-user.target

[Service]
User=root
WorkingDirectory=$CURRENT_DIR
Type=simple
ExecStart=/usr/bin/python3 $CURRENT_DIR/faitour.py
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
EOF
echo 'done.'


#===============================================================================
# Enable the Service
#===============================================================================
printf 'Reloading system daemon and enabling Faitour service... '
sudo systemctl daemon-reload
sudo systemctl enable faitour.service
echo 'done.'


#===============================================================================
# That should be it!
#===============================================================================
printf "\n\n  Setup is complete! To finalize the installation:\n"
printf "    * Update the configuration in /opt/Faitour/configuration/host_config.ini\n"
printf "      - IMPORTANT! The 'ip' and 'interface' fields must match your host's setup, or spoofing will not work!\n"
printf "      - Samples configs may be found in /opt/Faitour/configuration/sample_configs\n"
printf "    * Start the service\n"
printf "      - sudo systemctl start faitour.service\n"
printf "    * Confirm Faitour is working by performing an NMAP scan from another device\n\n"
