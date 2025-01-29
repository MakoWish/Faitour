#!/usr/bin/python3

import os
import sys
import yaml
import socket
import psutil
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
		"python3-psutil"
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
		#subprocess.run(["systemctl", "enable", "faitour.service"], check=True)
		#subprocess.run(["systemctl", "start", "faitour.service"], check=True)
		log("Systemd service created and started successfully.")
	except Exception as e:
		log(f"Failed to create or start systemd service: {e}", "ERROR")
		sys.exit(1)


# Attempt to retrieve the primary network adapter details
def get_primary_network_adapter():
	log("Attempting to get network adapter details...")
	for interface, addrs in psutil.net_if_addrs().items():
		ip = None
		mac = None

		# Skip loopback interface
		if interface == "lo" or interface.startswith("lo"):
			continue

		# Check each address type
		for addr in addrs:
			if addr.family == socket.AF_INET:  # IPv4
				ip = addr.address
			elif addr.family == psutil.AF_LINK:  # MAC address
				mac = addr.address

		# Return only if both IP and MAC are valid
		if ip and mac:
			return {"name": interface, "ip": ip, "mac": mac}

	return None


# Prompt a yes/no question with a configurable default.
def prompt_yes_no(question: str, default: bool = True) -> bool:
	# Determine the default display string
	default_prompt = "[Y/n]" if default else "[y/N]"

	while True:
		response = input(f"{question} {default_prompt}: ").strip().lower()

		# Handle empty input based on the default
		if response == "":
			return default
		elif response in {"y", "yes"}:
			return True
		elif response in {"n", "no"}:
			return False
		else:
			print("Please enter 'y' or 'n' (or press Enter for the default).")


# Update YAML file with primary network adapter info.
def update_yaml_with_adapter_info(adapter_info):
	# Load existing YAML data or create a new structure
	config_data = {}
	if os.path.exists("./config.yml"):
		with open(yaml_file, "r") as file:
			config_data = yaml.safe_load(file) or {}

	# Update the relevant fields
	config_data["network"] = {
		"adapter": {
			"name": adapter_info["name"],
			"ip": adapter_info["ip"],
			"mac": adapter_info["mac"],
		}
	}

	# Write back to the YAML file
	with open(yaml_file, "w") as file:
		yaml.dump(config_data, file)

	log("Updated ./config.yml with adapter information:")
	log(f"Name: {adapter_info['name']}")
	log(f"IP: {adapter_info['ip']}")
	log(f"MAC: {adapter_info['mac']}")


# Main routine
def main():
	check_root()
	install_apt_packages()
	install_pip_packages()
	create_systemd_service()

	# Try to automatically set network details
	adapter = get_primary_network_adapter()
	if not adapter:
		log("No active non-loopback network adapters found.", "ERROR")
		log("You will need to set your network details in `config.yml` manually.", "ERROR")
	else:
		log("Network adapter found:\n")
		print(f"\tAdapter Name: {adapter['name']}")
		print(f"\tIP Address: {adapter['ip']}")
		print(f"\tMAC Address: {adapter['mac']}\n")
		if prompt_yes_no("Would you like to use these settings?", default=True):
			print("Set adapter details!")

	log("Installation complete. Exiting...")


# Entry point
if __name__ == "__main__":
	main()
