import socket
import subprocess
import threading
import time
import utils.config as config
from handlers.inspect import inspector
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT
from scapy.all import ICMP, IP, TCP, UDP
from scapy.contrib.igmp import IGMP
from utils.logger import appLogger
from utils.logger import honeyLogger
from utils.whitelist import is_whitelisted, load_whitelist


#===============================================================================
# Function to handle intercepted packets
#===============================================================================
def handle_packet(nfq_packet):
	try:
		packet = IP(nfq_packet.get_payload())
	except Exception as e:
		appLogger.error(f'"type":["protocol","error"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"intercept_packet","reason":"Failed to get packet payload","outcome":"failure"}},"error":{{"message":"{e}"')
		nfq_packet.accept()
		return 1

	try:
		if packet.haslayer(IP):
			ip = packet[IP]

			# Automatically forward any packets destined for localhost
			if ip.dst == "127.0.0.1":
				nfq_packet.accept()
				return 0

			# Analyze and process TCP packets
			if packet.haslayer(TCP):
				tcp = packet[TCP]
				ip = packet[IP]

				# If config.yml set to log SYN packets, log them for port scan detection
				if (tcp.flags == "S" and tcp.ack == 0 and log_tcp_syn and not is_whitelisted(ip.src, whitelist_networks)):
					honeyLogger.info(f'"type":["connection","start","allowed"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"intercept_packet","reason":"SYN packet received","outcome":"success"}},"source":{{"ip":"{ip.src}","port":{tcp.sport}}},"destination":{{"ip":"{ip.dst}","port":{tcp.dport}')

				# Inspect this TCP packet to see if it's part of an OS probe
				if not inspector.is_tcp_os_probe(nfq_packet, packet):
					# Accept the packet since it is not an OS probe
					nfq_packet.accept()

			# Analyze and process UDP packets
			elif packet.haslayer(UDP):
				if not inspector.is_udp_os_probe(nfq_packet, packet):
					# Accept the packet since it is not an OS probe
					nfq_packet.accept()

			# Analyze and process ICMP packets
			elif packet.haslayer(ICMP):
				if not inspector.is_icmp_os_probe(nfq_packet, packet):
					# Accept the packet since it is not an OS probe
					nfq_packet.accept()

			# Currently not doing anything with IGMP packets
			elif packet.haslayer(IGMP):
				nfq_packet.accept()

			else:
				# Unable to determine packet details. Forward it...
				appLogger.debug(f'"type":["connection","protocol","info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"intercept_packet","reason":"No current handler for protocol {ip.proto} from {ip.src}","outcome":"success"')
				nfq_packet.accept()

		else:
			appLogger.debug('"type":["connection","protocol","info"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"intercept_packet","reason":"Non-IP packet received","outcome":"success"')
			nfq_packet.accept()

	except Exception as e:
		appLogger.error(f'"type":["error"],"kind":"event","category":["network"],"dataset":"faitour.application","action":"intercept_packet","reason":"{e}","outcome":"failure"}},"error":{{"message":"{e}"')
		nfq_packet.accept()
		return 1

	return 0


#===============================================================================
# Function to add rules to iptables
#===============================================================================
FAITOUR_CHAIN = "FAITOUR"
SYSCTL_KEYS = (
	"net.ipv4.conf.all.arp_ignore",
	"net.ipv4.conf.all.arp_announce",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv4.ip_forward",
)
original_sysctls = {}


def _run(command, check=True):
	return subprocess.run(command, stdout=DEVNULL, stderr=STDOUT, check=check)


def set_rules():
	for key in SYSCTL_KEYS:
		original_sysctls[key] = subprocess.check_output(["sysctl", "-n", key], text=True).strip()
	for key, value in {
		"net.ipv4.conf.all.arp_ignore": "1",
		"net.ipv4.conf.all.arp_announce": "2",
		"net.ipv4.conf.all.rp_filter": "2",
		"net.ipv4.ip_forward": "1",
	}.items():
		_run(["sysctl", "-w", f"{key}={value}"])
	_run(["iptables", "-N", FAITOUR_CHAIN], check=False)
	_run(["iptables", "-F", FAITOUR_CHAIN])
	if _run(["iptables", "-C", "INPUT", "-j", FAITOUR_CHAIN], check=False).returncode != 0:
		_run(["iptables", "-I", "INPUT", "-j", FAITOUR_CHAIN])
	for protocol in ("tcp", "udp", "icmp"):
		_run(["iptables", "-A", FAITOUR_CHAIN, "-p", protocol, "!", "-d", "127.0.0.1", "-j", "NFQUEUE", "--queue-num", "2", "--queue-bypass"])


#===============================================================================
# Function to flush iptables and rules when shutting down
#===============================================================================
def flush_rules():
	while _run(["iptables", "-D", "INPUT", "-j", FAITOUR_CHAIN], check=False).returncode == 0:
		pass
	_run(["iptables", "-F", FAITOUR_CHAIN], check=False)
	_run(["iptables", "-X", FAITOUR_CHAIN], check=False)
	for key, value in original_sysctls.items():
		_run(["sysctl", "-w", f"{key}={value}"], check=False)


#===============================================================================
# Function to monitor NFQUEUE queue size in a separate thread
#===============================================================================
def monitor_nfqueue_queue_size(nfqueue, max_queue_size, stop_event, interval=1):
	while not stop_event.is_set():  # Check if the stop event is set
		try:
			with open("/proc/net/netfilter/nfnetlink_queue", "r") as f:
				# Read the queue stats
				line = f.readline().strip()
				if line:
					columns = line.split()
					if len(columns) > 2:
						queue_size = int(columns[2])  # Third column is the queue size

						if queue_size > (max_queue_size - 100):
							appLogger.warn(f'"type":["info"],"kind":"metric","category":["process"],"dataset":"faitour.application","action":"monitor_nfqueue_queue_size","reason":"NFQUEUE size {queue_size} approaching threshold of {max_queue_size}","outcome":"unknown"')

							# I am keeping this service restart as a fail-safe to ensure no conflicts with Elastic Agent, but
							# I believe the recent change to the IP Tables rule renders this entire queue monitoring method obsolete.
							appLogger.warn('"type":["info","start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"bind_nfqueue","reason":"Restart Faitour service...","outcome":"unknown"')
							subprocess.run(["systemctl", "restart", "faitour.service"], check=False)
							appLogger.info('"type":["info","start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"bind_nfqueue","reason":"Restarted Faitour service","outcome":"success"')
					else:
						appLogger.warn('"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"monitor_nfqueue_queue_size","reason":"Unexpected format in /proc/net/netfilter/nfnetlink_queue","outcome":"unknown"')
				else:
					appLogger.warn('"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"monitor_nfqueue_queue_size","reason":"/proc/net/netfilter/nfnetlink_queue is empty or unreadable","outcome":"unknown"')

					# Issue with queue. Restart the service
					appLogger.error('"type":["info","start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"bind_nfqueue","reason":"Restart Faitour service...","outcome":"unknown"')
					subprocess.run(["systemctl", "restart", "faitour.service"], check=False)
					appLogger.info('"type":["info","start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"bind_nfqueue","reason":"Restarted Faitour service","outcome":"success"')
		except FileNotFoundError as e:
			appLogger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"monitor_nfqueue_queue_size","reason":"/proc/net/netfilter/nfnetlink_queue not found","outcome":"failure"}},"error":{{"message":"{e}"}}')

			# Restart the service since it appears NFQUEUE may not be running
			appLogger.warn('"type":["info","start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"bind_nfqueue","reason":"Restart Faitour service...","outcome":"unknown"')
			subprocess.run(["systemctl", "restart", "faitour.service"], check=False)
			appLogger.info('"type":["info","start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"bind_nfqueue","reason":"Restarted Faitour service","outcome":"success"')
		except Exception as e:
			appLogger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"monitor_nfqueue_queue_size","reason":"Error monitoring NFQUEUE queue size","outcome":"failure"}},"error":{{"message":"{e}"}}')

		# Sleep for the specified interval before checking again
		time.sleep(interval)


def start(max_queue_size):
	# Check to see if we should be logging SYN packets
	global log_tcp_syn
	log_tcp_syn = config.get_value("syn_logging")["tcp"]

	# Load IP addresses and CIDR ranges whose SYN packets should not be logged
	global whitelist_networks
	def warn_invalid_whitelist_entry(line_number, _entry):
		appLogger.warning(f'"type":["error"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"load_whitelist","reason":"Ignoring invalid whitelist entry on line {line_number}","outcome":"failure"')
	whitelist_networks = load_whitelist(invalid_entry_callback=warn_invalid_whitelist_entry)

	# Set our iptables and network rules
	appLogger.info('"type":["info","change"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"start","reason":"Network and iptables rules are being set","outcome":"unknown"')
	try:
		set_rules()
	except Exception:
		flush_rules()
		raise
	appLogger.info('"type":["info","change"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"end","reason":"Network and iptables rules have been set","outcome":"success"')

	# Create a NetfilterQueue object and bind it to queue number 2
	nfqueue = NetfilterQueue()
	try:
		nfqueue.bind(2, handle_packet, max_len=max_queue_size)
		s = socket.fromfd(nfqueue.get_fd(), socket.AF_INET, socket.SOCK_STREAM)
	except Exception:
		flush_rules()
		raise

	# Create a stop event for the monitor thread
	stop_event = threading.Event()

	# Start the NFQUEUE size monitoring in a separate thread
	monitor_thread = threading.Thread(target=monitor_nfqueue_queue_size, args=(nfqueue, max_queue_size, stop_event, 2))
	monitor_thread.daemon = True  # Ensure it terminates when the main program ends
	monitor_thread.start()

	exit_code = 0
	try:
		# Run the main nfqueue socket in the main thread
		appLogger.info('"type":["info","start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"NFQUEUE socket is now intercepting packets","outcome":"success"')
		nfqueue.run_socket(s)

	except KeyboardInterrupt:
		appLogger.info('"type":["info","end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"end","reason":"Shutting down Faitour due to keyboard interrupt","outcome":"success"')
	except Exception as e:
		appLogger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"end","reason":"Shutting down Faitour due to unknown exception","outcome":"failure"}},"error":{{"message":"{e}"}}')
		exit_code = 1
	finally:
		# Clean up resources
		appLogger.info('"type":["info","change"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"start","reason":"Network and iptables rules are being reset","outcome":"unknown"')
		flush_rules()
		appLogger.info('"type":["info","change"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"end","reason":"Network and iptables rules have been reset","outcome":"success"')

		appLogger.info('"type":["info","start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"Unbinding NFQUEUE","outcome":"unknown"')
		nfqueue.unbind()
		appLogger.info('"type":["info","end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"end","reason":"NFQUEUE has been unbound","outcome":"success"')

		# Signal the monitor thread to stop and wait for it to finish
		if monitor_thread.is_alive():
			appLogger.info('"type":["info","start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"Terminating NFQUEUE monitor","outcome":"unknown"')
			stop_event.set()
			monitor_thread.join()
			appLogger.info('"type":["info","end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"end","reason":"Terminated NFQUEUE monitor","outcome":"success"')

	return exit_code
