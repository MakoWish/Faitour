from Tunnel.packetBackUp import startIntercept
from Tunnel.VirtualDevice import addNewDevice
import configparser
from xeger import Xeger
import logging.handlers
import os
from multiprocessing import Process
import gconstant as gc


#===============================================================================
# Main program function
#===============================================================================
def main():
    gc.LOGGER.info('Starting Faitour...')

    #  Configparser to read configurations
    config = configparser.ConfigParser(interpolation=None)
    config.read(os.path.dirname(os.path.realpath(__file__)) + '/configuration/host_config.ini')

    #  Get Host Machine IP & MAC Address
    gc.LOGGER.debug('Get IP and MAC address from configuration')
    ip, mac_addr = config.get('CONFIGURATION', 'ip', fallback=None), config.get('CONFIGURATION', 'mac_address', fallback=None)
    gc.LOGGER.debug('Retrieved IP as ' + ip + ' and MAC as ' + mac_addr)
    if ip is None:
        return

    #  Services (Specified in Configuration File)
    services = dict()
    for key in config['HOST']:
        try:
            services[int(key)] = process(config['HOST'][key])
        except ValueError:
            pass

    #  Add Device To Subnet
    addNewDevice(name='HOST', services=services, fingerprint=config.get('HOST', 'fingerprint'), ip=ip, mac_addr=mac_addr)

    # Start intercepting traffic
    startIntercept()


#===============================================================================
# Parse OS and service fingerprints
#===============================================================================
def process(data, limit=10, increment=100):
    #  Process Regex - Increment 150 ~ 7.9 seconds
    try:
        x = Xeger(limit)
        val = x.xeger(data)
    except ValueError:
        val = process(data, limit+increment, increment)
    return val


#===============================================================================
# Entry point
#===============================================================================
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        gc.LOGGER.info('Attempting to cleanly shutdown Faitour...')
        try:
            try:
                gc.LOGGER.info('Deleting NFQUEUE rule from iptables...')
                subprocess.run(['iptables', '-D', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '2'], stdout=DEVNULL, stderr=STDOUT)
            except:
                # The rule did not exist
                gc.LOGGER.warning('NFQUEUE rule did not exist in iptables.')
            gc.LOGGER.info('Flushing IPTABLES...')
            subprocess.run(['iptables', '-F'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            gc.LOGGER.info('Faitour has stopped.')
            sys.exit(0)
        except SystemExit:
            os._exit(0)
