import base64
import socket
import threading
import utils.config as config
import handlers.fingerprint as fingerprint
import handlers.spoof as spoof
from netfilterqueue import NetfilterQueue
from subprocess import DEVNULL, STDOUT, check_call
from scapy.all import *
from scapy.contrib.igmp import IGMP
from utils.logger import logger


#===============================================================================
# Function to handle intercepted packets
#===============================================================================
def handle_packet(nfq_packet):
	try:
		packet = IP(nfq_packet.get_payload())
	except Exception as e:
		logger.error(f'"type":["error"],"kind":"event","category":["network"],"dataset":"application","action":"handle_packet","reason":"Failed to get packet payload","outcome":"failure"}},"error":{{"message":"{e}"')
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

				syn_packet = (tcp.flags == "S" and tcp.ack == 0)

				if syn_packet:
					if log_tcp_syn:
						logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"handle_packet","reason":"SYN packet received","outcome":"success"}},"source":{{"ip":"{ip.src}","port":{tcp.sport}}},"destination":{{"ip":"{ip.dst}","port":{tcp.dport}')
					nfq_packet.accept()
				else:
					nfq_packet.accept()

			# Analyze and process UDP packets
			elif packet.haslayer(UDP):
				# More work to do here
				nfq_packet.accept()

			# Analyze and process ICMP packets
			elif packet.haslayer(ICMP):
				# Not sure if I want to do more here
				nfq_packet.accept()

			# Currently not doing anything with IGMP packets
			elif packet.haslayer(IGMP):
				nfq_packet.accept()

			else:
				# Unable to determine packet details. Forward it...
				logger.debug(f'"type":["connection","protocol","info"],"kind":"event","category":["network"],"dataset":"application","action":"handle_packet","reason":"No current handler for protocol {ip.proto} from {ip.src}","outcome":"success"')
				nfq_packet.accept()

		else:
			logger.debug(f'"type":["connection","protocol","info"],"kind":"event","category":["network"],"dataset":"application","action":"handle_packet","reason":"Non-IP packet received","outcome":"success"')
			nfq_packet.accept()
		
	except Exception as e:
		logger.error(f'"type":["error"],"kind":"event","category":["network"],"dataset":"application","action":"handle_packet","reason":"{e}","outcome":"failure"}},"error":{{"message":"{e}"')
		nfq_packet.accept()
		return 1

	return 0


#===============================================================================
# Function to add rules to iptables
#===============================================================================
def set_rules():
	check_call(["sysctl", "net.ipv4.conf.all.arp_ignore=1"], stdout=DEVNULL, stderr=STDOUT)
	check_call(["sysctl", "net.ipv4.conf.all.arp_announce=2"], stdout=DEVNULL, stderr=STDOUT)
	check_call(["sysctl", "net.ipv4.conf.all.rp_filter=2"], stdout=DEVNULL, stderr=STDOUT)
	check_call(["echo 1 | tee /proc/sys/net/ipv4/ip_forward"], stdout=DEVNULL, stderr=STDOUT, shell=True)
	check_call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "2"], stdout=DEVNULL, stderr=STDOUT)


#===============================================================================
# Function to flush iptables and rules when shutting down
#===============================================================================
def flush_rules():
	check_call(["sysctl", "net.ipv4.conf.all.arp_ignore=0"], stdout=DEVNULL, stderr=STDOUT)
	check_call(["sysctl", "net.ipv4.conf.all.arp_announce=0"], stdout=DEVNULL, stderr=STDOUT)
	check_call(["sysctl", "net.ipv4.conf.all.rp_filter=0"], stdout=DEVNULL, stderr=STDOUT)
	check_call(["echo 0 | tee /proc/sys/net/ipv4/ip_forward"], stdout=DEVNULL, stderr=STDOUT, shell=True)
	check_call(["iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", "2"], stdout=DEVNULL, stderr=STDOUT)


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
							logger.warn(f'"type":["info"],"kind":"metric","category":["process"],"dataset":"application","action":"monitor_nfqueue_queue_size","reason":"NFQUEUE size {queue_size} approaching threshold of {max_queue_size}","outcome":"success"')

							# Unbind and re-bind the NFQUEUE
							nfqueue.unbind()
							nfqueue.bind(2, handle_packet, max_len=queue_size)
							logger.info(f'"type":["info"],"kind":"metric","category":["process"],"dataset":"application","action":"monitor_nfqueue_queue_size","reason":"NFQUEUE re-bound due to queue size exceeding threshold","outcome":"success"')
					else:
						logger.warn(f'"type":["info"],"kind":"event","category":["process"],"dataset":"application","action":"monitor_nfqueue_queue_size","reason":"Unexpected format in /proc/net/netfilter/nfnetlink_queue","outcome":"success"')
				else:
					logger.warn(f'"type":["info"],"kind":"event","category":["process"],"dataset":"application","action":"monitor_nfqueue_queue_size","reason":"/proc/net/netfilter/nfnetlink_queue is empty or unreadable","outcome":"success"')
		except FileNotFoundError as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"monitor_nfqueue_queue_size","reason":"/proc/net/netfilter/nfnetlink_queue not found","outcome":"failure"}},"error":{{"message":"{e}"}}')
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"monitor_nfqueue_queue_size","reason":"Error monitoring NFQUEUE queue size","outcome":"failure"}},"error":{{"message":"{e}"}}')
		
		# Sleep for the specified interval before checking again
		time.sleep(interval)

	logger.info(f'"type":["info","end"],"kind":"event","category":["process"],"dataset":"application","action":"monitor_nfqueue_queue_size","reason":"Monitor thread exiting","outcome":"success"')


def start(max_queue_size):
	# Check to see if we should be logging SYN packets
	global log_tcp_syn
	log_tcp_syn = config.get_value("syn_logging")["tcp"]

	# Set our iptables and network rules
	set_rules()
	logger.info(f'"type":["info","change"],"kind":"event","category":["process"],"dataset":"application","action":"start","reason":"Network and iptables rules have been set","outcome":"success"')

	# Create a NetfilterQueue object and bind it to queue number 2
	nfqueue = NetfilterQueue()
	nfqueue.bind(2, handle_packet, max_len=max_queue_size)
	s = socket.fromfd(nfqueue.get_fd(), socket.AF_INET, socket.SOCK_STREAM)

	# Create a stop event for the monitor thread
	stop_event = threading.Event()

	# Start the NFQUEUE size monitoring in a separate thread
	monitor_thread = threading.Thread(target=monitor_nfqueue_queue_size, args=(nfqueue, max_queue_size, stop_event, 2))
	monitor_thread.daemon = True  # Ensure it terminates when the main program ends
	monitor_thread.start()

	try:
		# Run the main nfqueue socket in the main thread
		logger.info(f'"type":["info","start"],"kind":"event","category":["process"],"dataset":"application","action":"start","reason":"NFQUEUE socket is now intercepting packets","outcome":"success"')
		nfqueue.run_socket(s)

	except KeyboardInterrupt:
		logger.info(f'"type":["info","stop"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"Shutting down Faitour due to keyboard interrupt","outcome":"success"')
	except Exception as e:
		logger.info(f'"type":["info","stop"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"Shutting down Faitour due to unknown exception","outcome":"failure"}},"error":{{"message":"{e}"}}')
	finally:
		# Clean up resources
		flush_rules()
		logger.info(f'"type":["info","change"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"Network and iptables rules have been reset","outcome":"success"')

		nfqueue.unbind()
		logger.info(f'"type":["info","change"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"NFQUEUE has been unbound","outcome":"success"')

		# Signal the monitor thread to stop and wait for it to finish
		if monitor_thread.is_alive():
			stop_event.set()
			monitor_thread.join()
			logger.info(f'"type":["info","change"],"kind":"event","category":["process"],"dataset":"application","action":"stop","reason":"NFQUEUE monitor stopped","outcome":"success"')

	return 0