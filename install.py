#!/usr/bin/python3

import os
import sys
import subprocess


# Log to console
def log(message, level="INFO"):
	print(f"[{level}] {message}")


# Ensure this install is being run as root/sudo
def check_root():
	if os.geteuid() != 0:
		log("This script must be run as root.", "ERROR")
		sys.exit(1)


# Install required packages from apt
def install_apt_packages():
	apt_packages = [
		"build-essential",
		"libnetfilter-queue-dev",
		"python3",
		"python3-pip",
		"python3-scapy",
		"python3-pysmi",
		"python3-pyftpdlib",
		"python3-paramiko",
	]
	try:
		log("Updating apt package list...")
		subprocess.run(["apt", "update"], check=True)
		
		log("Installing apt packages...")
		subprocess.run(["apt", "install", "-y"] + apt_packages, check=True)
		log("Apt packages installed successfully.")
	except subprocess.CalledProcessError:
		log("Failed to install apt packages.", "ERROR")
		sys.exit(1)


# Install Python packages that are not available in apt
def install_pip_packages():
	pip_packages = [
		"netfilterqueue",
		"pysnmp",
		"smbprotocol",
		"telnetlib3"
	]
	try:
		log("Installing pip packages...")
		subprocess.run(["pip3", "install", "--break-system-packages"] + pip_packages, check=True)
		log("Pip packages installed successfully.")
	except subprocess.CalledProcessError:
		log("Failed to install pip packages.", "ERROR")
		sys.exit(1)


# Create systemd service to start Faitour on system restart
def create_systemd_service():
	service_content = f"""[Unit]
Description=Faitour Services Emulator
After=network.target

[Service]
ExecStart=/usr/bin/python3 {os.path.abspath('faitour.py')}
WorkingDirectory={os.path.abspath('.')}
Restart=always
User=root
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
"""
	service_path = "/etc/systemd/system/faitour.service"
	try:
		log("Creating systemd service file...")
		with open(service_path, "w") as service_file:
			service_file.write(service_content)

		log("Reloading systemd daemon...")
		subprocess.run(["systemctl", "daemon-reload"], check=True)

		log("Enabling and starting the service...")
		subprocess.run(["systemctl", "enable", "faitour.service"], check=True)
		subprocess.run(["systemctl", "start", "faitour.service"], check=True)
		log("Systemd service created and started successfully.")
	except Exception as e:
		log(f"Failed to create or start systemd service: {e}", "ERROR")
		sys.exit(1)


# Main
def main():
	check_root()
	install_apt_packages()
	install_pip_packages()
	create_systemd_service()


# Entry point
if __name__ == "__main__":
	main()
