#!/usr/bin/python3

import os
import time
import utils.config as config
import handlers.intercept as intercept
from utils.emulators import ServiceEmulators
from utils.logger import logger


#===============================================================================
# Main function to start Faitour
#===============================================================================
def main():
	# Ensure we are running as root/sudo
	if os.geteuid() != 0:
		logger.critical('"type":["start","error","denied"],"kind":"event","category":["process"],"dataset":"application","action":"application_start","reason":"Application must be run as root/sudo","outcome":"failure"')
		os._exit(5)

	# Ensure our configuration looks okay
	if not config.is_valid():
		logger.critical('"type":["start","error"],"kind":"event","category":["process"],"dataset":"application","action":"check_config","reason":"Default configuration found","outcome":"failure"')
		return False

	# Note that the application is starting
	logger.info('"type":["start","info"],"kind":"event","category":"process","dataset":"application","action":"application_start","reason":"Faitour is starting","outcome":"success"')

	# Start any emulators that are enabled
	emulators = ServiceEmulators()
	emulators.start()

	# Get our configured maximum NFQUEUE size
	max_queue_size = config.get_value("network.max_queue_size")

	# Start intercepting packets
	intercept.start(max_queue_size)


#===============================================================================
# Application entry point
#===============================================================================
if __name__ == "__main__":
	try:
		main()
	except Exception as e:
		logger.error(f'"type":["end","error"],"kind":"event","category":["process"],"dataset":"application","action":"application_stop","reason":"{e}","outcome":"failure"')
	finally:
		logger.info('"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"application_stop","reason":"Faitour has stopped","outcome":"success"')
		os._exit(0)
