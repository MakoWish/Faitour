import yaml
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
# Return the list of services where 'enabled' is True.
#===============================================================================
def get_enabled_services():
    enabled_services = []
    for service in get_services():
        if service.get('enabled', False):
            enabled_services.append(service)
    return enabled_services


#===============================================================================
# Fetch a service by its name.
#===============================================================================
def get_service_by_name(name):
	for service in get_services():
		if service.get('name') == name:
			return service
	return None


#===============================================================================
# Get the fingerprint to return for a given port number
#===============================================================================
def get_fingerprint(src_port):
	for service in enabled_services:
			if service["port"] == src_port:
				fingerprint = bytes(service['fingerprint'], "utf-8").decode("unicode_escape")
				return fingerprint


#===============================================================================
# Verify network details have been configured (not default from Git)
#===============================================================================
def is_valid():
	if get_value("network.adapter.name") == "change_me":
		return False
	if get_value("network.adapter.ip") == "10.0.0.0":
		return False
	if get_value("network.adapter.mac") == "00:11:22:33:44:55":
		return False
	return True


# Get the entire configuration to variable
config = load_config()

# If our configuration is not default, get our interface
if is_valid():
	if_name = get_value("network.adapter.name")
	if_sock = conf.L3socket(iface=if_name)
