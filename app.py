from Tunnel.packetBackUp import startIntercept
from Tunnel.VirtualDevice import addNewDevice
import configparser
from xeger import Xeger
import logging.handlers
import os
from multiprocessing import Process
import gconstant as gc


def main():
    #  Configparser to read configurations
    config = configparser.ConfigParser(interpolation=None)
    config.read(os.path.dirname(os.path.realpath(__file__)) + '/configuration/host_config.ini')
    print("Starting Program...")

    debug = logging.getLogger('faitour-debug')

    if config.getboolean('CONFIGURATION', 'debug', fallback=False):
        debug.debug('#'*50)
        debug.debug('Starting Program...')

    #  Get Host Machine IP & MAC Address
    ip, mac_addr = config.get('HOST', 'ip', fallback=None), config.get('HOST', 'mac_address', fallback=None)
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
    addNewDevice(name='HOST', services=services, fingerprint=config.get('HOST', 'fingerprint'),
                 ip=ip, mac_addr=mac_addr)
    # addNewDevice(name='Test', services=service, fingerprint=host['fingerprint'], ip='192.168.1.1', macAddr=mac_addr)

    print('Done Loading...')
    debug.debug('Done Loading...')
    startIntercept()


def process(data, limit=10, increment=100):
    #  Process Regex - Increment 150 ~ 7.9 seconds
    try:
        x = Xeger(limit)
        val = x.xeger(data)
    except ValueError:
        val = process(data, limit+increment, increment)
    return val


if __name__ == "__main__":
    main()
