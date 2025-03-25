import os
import requests
import shutil
import logging
from pathlib import Path
from zipfile import ZipFile
from utils.logger import logger


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
		logger.error('"type":["start","error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"Local version file not found","outcome":"failure"')
		return None


# Check the version on GitHub
def get_remote_version():
	try:
		response = requests.get(REPO_VERSION_URL, timeout=5)
		response.raise_for_status()
		return response.text.strip()
	except requests.RequestException as e:
		logger.error(f'"type":["start","error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"Error fetching remote version: {e}","outcome":"failure"')
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

		logger.info('"type":["start","info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"reason","reason":"Update applied successfully.","outcome":"success"')
	except Exception as e:
		logger.error(f'"type":["start","error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"Update failed: {e}","outcome":"failure"')


# Main function
def main(check_only=False):
	local_version = get_local_version()
	remote_version = get_remote_version()

	if not local_version or not remote_version:
		return

	if local_version < remote_version:
		logger.info(f'"type":["start","info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"reason","reason":"A newer version ({remote_version}) is available. Please","outcome":"success"')
		user_input = input(f"A newer version ({remote_version}) is available. Update now? (y/n): ").strip().lower()
		if user_input == "y":
			download_and_extract()
			print("Update completed. Please restart the application.")
		else:
			print("Update skipped.")
	else:
		print("You are already on the latest version.")


# Module entry point
if __name__ == "__main__":
	main()
