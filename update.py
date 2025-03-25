#!/usr/bin/python3

import os
import requests
import shutil
import logging
from pathlib import Path
from zipfile import ZipFile


GITHUB_REPO = "https://github.com/MakoWish/Faitour2"
VERSION_FILE = "version.txt"
REPO_VERSION_URL = f"{GITHUB_REPO}/raw/main/{VERSION_FILE}"
ZIP_URL = f"{GITHUB_REPO}/archive/main.zip"
EXCLUDE_FILES = {"config.yml"}
EXCLUDE_FOLDERS = {"emulators/ftp_root", "emulators/http_root", "emulators/ssh_root", "emulators/telnet_root"}


# Check the locally installed version
def get_local_version():
	try:
		with open(VERSION_FILE, "r") as f:
			return f.read().strip()
	except FileNotFoundError:
		return None


# Check the version on GitHub
def get_remote_version():
	try:
		response = requests.get(REPO_VERSION_URL, timeout=5)
		response.raise_for_status()
		return response.text.strip()
	except requests.RequestException as e:
		return None


# Download and extract from GitHub
def download_and_extract():
	try:
		zip_path = "update.zip"
		response = requests.get(ZIP_URL, stream=True)
		with open(zip_path, "wb") as f:
			for chunk in response.iter_content(1024):
				f.write(chunk)

		with ZipFile(zip_path, "r") as zip_ref:
			extracted_folder = "Faitour2-main"
			zip_ref.extractall()

			for item in Path(extracted_folder).rglob("*"):
				relative_path = item.relative_to(extracted_folder)
				if relative_path.name in EXCLUDE_FILES or any(folder in relative_path.parts for folder in EXCLUDE_FOLDERS):
					continue

				dest = Path.cwd() / relative_path
				if item.is_dir():
					dest.mkdir(parents=True, exist_ok=True)
				else:
					shutil.move(str(item), str(dest))

		shutil.rmtree(extracted_folder)
		os.remove(zip_path)

		print("Update applied successfully.")
	except Exception as e:
		print(f"Update failed: {e}")


# Main function
def check(silent=False):
	# Ensure we are running as root/sudo
	if os.geteuid() != 0:
		print("This update script must be run as root/sudo!")
		os._exit(5)

	local_version = get_local_version()
	remote_version = get_remote_version()

	if not local_version or not remote_version:
		return

	if local_version < remote_version:
		if silent:
			return True
		else:
			user_input = input(f"A newer version ({remote_version}) is available. Update now? (y/n): ").strip().lower()
			if user_input == "y":
				download_and_extract()
				print("Update completed. Please restart the application.")
			else:
				print("Update skipped.")
	else:
		if silent:
			return False
		else:
			print("You are already on the latest version.")


# Module entry point
if __name__ == "__main__":
	check()
