import pkgutil
import inspect
import logging
from logging.handlers import RotatingFileHandler
import logging.handlers
import configparser
import os
import subprocess
from scapy.all import conf
from Cryptodome.PublicKey import RSA


#===============================================================================
# Configure our logger
#===============================================================================
def logger_config(logName, stdout, raw):
    # Get logger details from host_config.ini
    config = configparser.ConfigParser(interpolation=None)
    config.read(os.path.dirname(os.path.realpath(__file__)) + '/configuration/host_config.ini')
    logDir = config.get('LOGGING', 'logDir', fallback="/var/log/faitour/")
    logLevel = config.get('LOGGING', 'logLevel', fallback="INFO")
    logSize = config.getint('LOGGING', 'logSize', fallback=10000000)
    logCount = config.getint('LOGGING', 'logCount', fallback=10)

    # Create a new logger and set to declared level
    logger = logging.getLogger(logName)
    logger.setLevel(logging.getLevelName(logLevel))

    if stdout:
        # A file handler will be added later, but create a stdout stream logger here
        stdoutLogger = logging.StreamHandler()
        stdoutLogger.setFormatter(logging.Formatter('%(name)s (%(levelname)s): %(message)s'))
        logger.addHandler(stdoutLogger)

    # Note that logger has been configured
    logger.info('Logging level set to ' + logLevel + '.')

    # Ensure we have write access to our log location
    if checkLogPath(logger, logDir):
        # Use a RotatingFileHandler for our file logger (log => log.1 => log.2 => ...)
        fileLogger = RotatingFileHandler(logDir + logName, maxBytes=logSize, backupCount=logCount)
        if raw:
            fileLogger.setFormatter(logging.Formatter('%(message)s'))
        else:
            fileLogger.setFormatter(logging.Formatter('%(asctime)s (%(levelname)s): %(message)s'))

        # Note the file we are logging to
        logger.info('Logging to "' + logDir + logName + '".')

        # Add both file and stdout handlers to the logger
        logger.addHandler(fileLogger)

    return logger


#===============================================================================
# Make sure our log file path exists and we have write access
#===============================================================================
def checkLogPath(logger, logDir):
    if os.path.exists(logDir):
        if os.access(logDir, os.W_OK):
            logger.info('Log file directory "' + logDir + '" exists and we have write access.')
            return True
        else:
            logger.critical('Log file directory "' + logDir + '" exists, but we do not have write access. Exiting...')
            exit(1)
    else:
        upOneDir = os.path.abspath(os.path.join(os.path.dirname(logDir), '..'))
        if os.path.exists(upOneDir):
            if os.access(upOneDir, os.W_OK):
                os.mkdir(logDir)
                logger.info('Log file directory "' + logDir + '" has been created.')
                return True
            else:
                logger.critical('"' + logDir + '" does not exist, and we do not have write access to "' + upOneDir + '" to create it. Exiting...')
                exit(1)
        else:
            logger.critical('"' + upOneDir + '" does not exist. Please check your log location settings and try again. Exiting...')
            exit(1)


#===============================================================================
# Get and validate interface details
#===============================================================================
def get_interface():
    global INTERFACE, SOCKET_INTERFACE
    config = configparser.ConfigParser(interpolation=None)
    config.read(os.path.dirname(os.path.realpath(__file__)) + '/configuration/host_config.ini')
    iface_ = config.get('CONFIGURATION', 'interface', fallback='ens33')

    try:
        LOGGER.debug('Getting device interface')
        INTERFACE = iface_
        SOCKET_INTERFACE = conf.L3socket(iface=iface_)
    except OSError:
        LOGGER.critical('Interface not found. Please check your host_config.ini')


#===============================================================================
# Verify Faitour is running as root/sudo
#===============================================================================
if os.geteuid() != 0:
    LOGGER.critical('You need to have root privileges to run Faitour')
    exit(0)


#===============================================================================
# Define loggers
#===============================================================================
# logger_config(logName, stdout, raw)
LOGGER = logger_config('faitour', True, False)
PACKET_LOGGER = logger_config('packets.json', False, True)


#===============================================================================
# Define global variables to be used by module
#===============================================================================
INTERFACE = None
SOCKET_INTERFACE = None


#===============================================================================
# Get interface details from fuction
#===============================================================================
get_interface()
