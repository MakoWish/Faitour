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
		"python3-psutil"
	]
	try:
		log("Updating apt package list...")
		subprocess.run(["apt", "update"], check=True)
		
		log("Installing apt packages...")
		subprocess.run(["apt", "install", "-y"] + apt_packages, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
		subprocess.run(["pip3", "install", "--break-system-packages"] + pip_packages, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
	except Exception as e:
		log(f"Failed to create or start systemd service: {e}", "ERROR")
		sys.exit(1)


# Function to enable and start the service
def enable_and_start():
	log("Enabling and starting the service...")
	subprocess.run(["systemctl", "enable", "faitour.service"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	subprocess.run(["systemctl", "start", "faitour.service"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	log("Systemd service created and started.")


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


# Main routine
def main():
	check_root()
	install_apt_packages()
	install_pip_packages()
	create_systemd_service()

	log("Installation complete.")
	log("Be sure to update your network settings in './config.yml'")


# Entry point
if __name__ == "__main__":
	main()
