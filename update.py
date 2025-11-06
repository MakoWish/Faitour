#!/usr/bin/python3

import os
import stat
import shutil
import requests
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


# Get a list of executable files to mark new as executable
def get_executable_files():
	exec_files = set()
	for item in Path.cwd().rglob("*"):
		if item.is_file() and os.access(item, os.X_OK):
			exec_files.add(str(item.relative_to(Path.cwd())))
	return exec_files


# Restore executable flag to files previously executable
def restore_executable_permissions(exec_files):
	for file in exec_files:
		file_path = Path.cwd() / file
		if file_path.exists():
			file_path.chmod(file_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# Ensure permissions are retained during file moves
def copy_with_permissions(src, dest):
    shutil.move(src, dest)
    st = os.stat(dest)
    os.chmod(dest, st.st_mode)


# Download and extract from GitHub
def download_and_extract():
	try:
		zip_path = "update.zip"
		response = requests.get(ZIP_URL, stream=True)
		with open(zip_path, "wb") as f:
			for chunk in response.iter_content(1024):
				f.write(chunk)

		exec_files = get_executable_files()

		with ZipFile(zip_path, "r") as zip_ref:
			extracted_folder = "Faitour2-main"
			zip_ref.extractall()

			for item in Path(extracted_folder).rglob("*"):
				relative_path = item.relative_to(extracted_folder)
				if relative_path.name in EXCLUDE_FILES or any(str(relative_path).startswith(folder) for folder in EXCLUDE_FOLDERS):
					continue

				dest = Path.cwd() / relative_path
				if item.is_dir():
					dest.mkdir(parents=True, exist_ok=True)
				else:
					copy_with_permissions(str(item), str(dest))

		shutil.rmtree(extracted_folder)
		os.remove(zip_path)
		restore_executable_permissions(exec_files)
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
		return False

	if local_version < remote_version:
		if silent:
			return True
		else:
			user_input = input(f"\n[!] A newer version ({remote_version}) is available.\n\nView the change log here: https://github.com/MakoWish/Faitour2/blob/main/changelog.txt\n\nUpdate from your current version ({local_version}) now? (y/n): ").strip().lower()
			if user_input == "y":
				download_and_extract()
				print("Update completed. Please restart the application.")
			else:
				print("Update skipped.")
	else:
		if silent:
			return False
		else:
			print(f"You are already on the latest version {local_version}.")


# Module entry point
if __name__ == "__main__":
	check()
