import ipaddress


#===============================================================================
# Load IP addresses and networks that should not generate SYN activity logs
#===============================================================================
def load_whitelist(file_path="whitelist", invalid_entry_callback=None):
	networks = []

	try:
		with open(file_path, "r") as file:
			for line_number, line in enumerate(file, start=1):
				entry = line.split("#", 1)[0].strip()
				if not entry:
					continue

				try:
					networks.append(ipaddress.ip_network(entry, strict=False))
				except ValueError:
					if invalid_entry_callback:
						invalid_entry_callback(line_number, entry)
	except FileNotFoundError:
		return []

	return networks


#===============================================================================
# Check whether an IP address belongs to a whitelisted address or CIDR range
#===============================================================================
def is_whitelisted(ip_address, networks):
	try:
		address = ipaddress.ip_address(ip_address)
	except ValueError:
		return False

	return any(address.version == network.version and address in network for network in networks)
