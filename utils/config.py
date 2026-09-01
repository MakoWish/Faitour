import yaml
import ipaddress
import logging
import socket
from scapy.all import conf


# The config file should be in the application's root
config_file = "config.yml"


#===============================================================================
# Load the complete configuration file
#===============================================================================
def load_config():
	with open(config_file, 'r') as file:
		return yaml.safe_load(file)


#===============================================================================
# Fetch a specific setting by its path (e.g. 'network.max_queue_size').
#===============================================================================
def get_value(setting_path):
	keys = setting_path.split('.')
	value = config
	for key in keys:
		value = value.get(key, None)
		if value is None:
			raise KeyError(f"Setting '{setting_path}' not found.")
	return value


#===============================================================================
# Return the list of all services.
#===============================================================================
def get_services():
	return config.get('services', [])


#===============================================================================
# Fetch a service by its name.
#===============================================================================
def get_service_by_name(name):
	for service in get_services():
		if service.get('name') == name:
			return service
	return None


#===============================================================================
# Verify network details have been configured (not default from Git)
#===============================================================================
def is_valid():
	return not validation_errors()


def validation_errors(check_interface=True):
	errors = []
	adapter = config.get("network", {}).get("adapter", {})
	if adapter.get("name") in (None, "change_me"):
		errors.append("network.adapter.name must be configured")
	elif check_interface and adapter["name"] not in {name for _, name in socket.if_nameindex()}:
		errors.append(f"network.adapter.name '{adapter['name']}' does not exist")
	try:
		address = ipaddress.ip_address(adapter.get("ip"))
		if address.is_unspecified:
			errors.append("network.adapter.ip cannot be an unspecified address")
	except (TypeError, ValueError):
		errors.append("network.adapter.ip must be a valid IP address")
	mac = adapter.get("mac", "")
	if mac == "00:11:22:33:44:55" or len(mac.split(":")) != 6:
		errors.append("network.adapter.mac must be configured as six colon-separated octets")
	if config.get("logging", {}).get("level") not in logging.getLevelNamesMapping():
		errors.append("logging.level is invalid")
	services = get_services()
	names = [service.get("name") for service in services]
	if len(names) != len(set(names)):
		errors.append("service names must be unique")
	ports = []
	for service in services:
		port = service.get("port")
		if not isinstance(port, int) or not 1 <= port <= 65535:
			errors.append(f"service '{service.get('name')}' has an invalid port")
		if service.get("enabled"):
			ports.append(port)
	if len(ports) != len(set(ports)):
		errors.append("enabled services must use unique ports")
	return errors


# Get the entire configuration to variable
config = load_config()

# If our configuration is not default, get our interface
if is_valid():
	if_name = get_value("network.adapter.name")
	if_sock = conf.L3socket(iface=if_name)
