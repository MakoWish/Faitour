import os
import time
import logging
import utils.config as config
from logging.handlers import RotatingFileHandler


#===============================================================================
# Class for logging based on application configuration
#===============================================================================
class Logger:
	def __init__(self):
		# Get the core values for our logger
		log_name = config.get_value('logging.name')
		log_level = config.get_value('logging.level')
		file_logging = config.get_value('logging.file.enabled')
		stdout_logging = config.get_value('logging.stdout.enabled')

		# Create our base logger object
		self.logger = logging.getLogger(log_name)
		self.logger.setLevel(logging.getLevelName(log_level))
		logging.Formatter.converter = time.gmtime

		if stdout_logging:
			# Add a stdout handler if enabled
			stdoutLogger = logging.StreamHandler()
			stdoutLogger.setFormatter(logging.Formatter('{"timestamp":"%(asctime)s.%(msecs)03d","log":{"level":"%(levelname)s","logger":"%(name)s","origin":{"file":{"line":%(lineno)s,"name":"%(pathname)s"}}},"event":{"provider":"%(module)s",%(message)s}}', datefmt='%Y-%m-%dT%H:%M:%S'))
			self.logger.addHandler(stdoutLogger)

			# Confirm that our stdout logger has been configured
			self.logger.debug(f'"type":["info"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"stdout_logging_start","reason":"Stdout logging has been initiated and set to {log_level}","outcome":"success"')

		if file_logging:
			# Add a file logger if enabled
			log_dir = config.get_value("logging.file.path")
			log_size = config.get_value('logging.file.size')
			log_count = config.get_value('logging.file.count')

			# Ensure we have write access to the logger location
			self.check_log_path(self.logger, log_dir)

			# Use a RotatingFileHandler for our file logger (log => log.1 => log.2 => ...)
			fileLogger = RotatingFileHandler(log_dir + log_name, maxBytes=log_size, backupCount=log_count)
			fileLogger.setFormatter(logging.Formatter('{"timestamp":"%(asctime)s.%(msecs)03d","log":{"level":"%(levelname)s","logger":"%(name)s","origin":{"file":{"line":%(lineno)s,"name":"%(pathname)s"}}},"event":{"provider":"%(module)s",%(message)s}}', datefmt='%Y-%m-%dT%H:%M:%S'))			

			# Add both file and stdout handlers to the logger
			self.logger.addHandler(fileLogger)

			# Confirm that our file logger has been configured
			self.logger.debug(f'"type":["info"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"file_logging_start","reason":"File logging to {log_dir}{log_name} and set to {log_level}","outcome":"success"')


	def check_log_path(self, logger, log_dir):
		if os.path.exists(log_dir):
			if os.access(log_dir, os.W_OK):
				logger.debug(f'"type":["info"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"check_log_path","reason":"Log file path {log_dir} exists with write access","outcome":"success"')
				return True
			else:
				logger.critical(f'"type":["error"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"check_log_path","reason":"Log file path {log_dir} exists, but we do not have write access","outcome":"failure"')
				os._exit(1)
		else:
			try:
				os.makedirs(log_dir)
				return True
			except Exception as e:
				logger.critical(f'"type":["error"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"check_log_path","reason":"Log file path {log_dir} does not exist, and it could not be created","outcome":"failure"}},"error":{{"message":"{e}"')
				os._exit(1)


	def get_logger(self):
		return self.logger


# Instantiate a shared instance of the Logger class
logger = Logger().get_logger()
