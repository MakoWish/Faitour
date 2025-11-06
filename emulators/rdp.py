import codecs
import socket
import threading
import utils.config as config
from utils.logger import appLogger
from utils.logger import honeyLogger

class RDServer:
	# Initialize the mock RDP server.
	def __init__(self):
		self.running = False
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("rdp")["port"]
		self.server_socket = None

	# Start the mock RDP server.
	def start(self):
		if self.running:
			appLogger.debug(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"RDP server emulator is already running","outcome":"success"')
			return

		try:
			appLogger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"RDP server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"unknown"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')
			self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable port reuse
			self.server_socket.bind((self.host_ip, self.host_port))
			self.server_socket.listen(5)
			self.running = True
			appLogger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"RDP server emulator started on {self.host_ip}:{self.host_port}","outcome":"success"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')

			# Start accepting connections in a separate thread
			threading.Thread(target=self.accept_connections, daemon=True).start()
		except Exception as e:
			appLogger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"handle_packet","reason":"RDP failed to start server","outcome":"failure"}},"error":{{"message":"{e}"')

	# Stop the mock RDP server.
	def stop(self):
		if not self.running:
			return

		try:
			appLogger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"RDP server emulator is stopping","outcome":"unknown"')
			if self.server_socket:
				self.server_socket.close()
				self.server_socket = None
			self.running = False
			appLogger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"RDP server emulator has stopped","outcome":"success"')
		except Exception as e:
			appLogger.error(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"handle_packet","reason":"RDP failed to stop server","outcome":"failure"}},"error":{{"message":"{e}"')

	# Handle incoming connections to the mock RDP server.
	def accept_connections(self):
		while self.running:
			try:
				client_socket, address = self.server_socket.accept()
				# Get client IP and port from address
				client_ip = address[0]
				client_port = address[1]
				
				honeyLogger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"accept_connections","reason":"RDP connection attempt","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
				
				# Handle the connection in a separate thread
				threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()
			except Exception as e:
				if self.running:  # Only log if server is running
					appLogger.error(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"accept_connections","reason":"RDP error accepting connections","outcome":"failure"}},"error":{{"message":"{e}"')

	# Simulate interaction with a client.
	def handle_client(self, client_socket, address):
		try:
			# Get client IP and port from address
			client_ip = address[0]
			client_port = address[1]

			# If initial data does not start with 0xFF, this is likely an NMAP service fingerprinting scan
			data = client_socket.recv(1024)
			if not data or data[0] != 0xff:
				honeyLogger.warning(f'"type":["connection","start"],"kind":"event","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"handle_client","reason":"Initial client data appears to be RDP service fingerprinting attempt","outcome":"unknown"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')

			honeyLogger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"handle_client","reason":"Simulating RDP handshake","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
		except Exception as e:
			appLogger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"handle_client","reason":"Error handling client","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			client_socket.close()
