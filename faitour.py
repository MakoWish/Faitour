#!/usr/bin/python3

import os
import sys
import time
import utils.config as config
import handlers.intercept as intercept
from update import check as update_available
from utils.emulators import ServiceEmulators
from utils.logger import appLogger


#===============================================================================
# Main function to start Faitour
#===============================================================================
def main():
	# Ensure we are running as root/sudo
	if os.geteuid() != 0:
		appLogger.critical('"type":["start","error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"Application must be run as root/sudo","outcome":"failure"')
		return 5

	# Ensure our configuration looks okay
	if not config.is_valid():
		appLogger.critical('"type":["error"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"check_config","reason":"Default configuration found","outcome":"failure"')
		return 2

	# Check if there are any updates available
	if update_available(silent=True):
		appLogger.info('"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"reason","reason":"An update is available. Please run \'update.py\' to apply these updates.","outcome":"unknown"')

	# Note that the application is starting
	appLogger.info('"type":["start","info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"reason","reason":"Faitour is starting","outcome":"unknown"')

	# Start any emulators that are enabled
	emulators = ServiceEmulators()
	emulators.start()

	# Get our configured maximum NFQUEUE size
	max_queue_size = config.get_value("network.max_queue_size")

	# Start intercepting packets
	try:
		return intercept.start(max_queue_size)
	finally:
		emulators.stop()


#===============================================================================
# Application entry point
#===============================================================================
if __name__ == "__main__":
	exit_code = 0
	try:
		exit_code = main()
	except Exception as e:
		appLogger.error(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"end","reason":"{e}","outcome":"failure"')
		exit_code = 1
	finally:
		time.sleep(2) # Pause just to give things time to fully shut down in case of a service restart
		outcome = "success" if exit_code == 0 else "failure"
		appLogger.info(f'"type":["end","info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"end","reason":"Faitour has stopped","outcome":"{outcome}"')
	sys.exit(exit_code)
