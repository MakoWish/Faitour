from utils.logger import logger
import utils.config as config
import socket
import threading

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
			return

		try:
			self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server_socket.bind((self.host_ip, self.host_port))
			self.server_socket.listen(5)
			self.running = True
			logger.info(f'"type":["start"],"kind":"event","category":["process"],"provider":"application","action":"start","reason":"RDP server emulator started on {self.host_ip}:{self.host_port}","outcome":"success"')

			# Start accepting connections in a separate thread
			threading.Thread(target=self._accept_connections, daemon=True).start()
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"provider":"application","action":"handle_packet","reason":"RDP failed to start server","outcome":"failure"}},"error":{{"message":"{e}"')

	# Stop the mock RDP server.
	def stop(self):
		if not self.running:
			return

		try:
			self.running = False
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"provider":"application","action":"stop","reason":"RDP server emulator is stopping","outcome":"success"')
			if self.server_socket:
				self.server_socket.close()
				self.server_socket = None
				logger.info(f'"type":["end"],"kind":"event","category":["process"],"provider":"application","action":"stop","reason":"RDP server emulator has stopped","outcome":"success"')
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"provider":"application","action":"handle_packet","reason":"RDP failed to stop server","outcome":"failure"}},"error":{{"message":"{e}"')

	# Handle incoming connections to the mock RDP server.
	def _accept_connections(self):
		while self.running:
			try:
				client_socket, client_address = self.server_socket.accept()
				client_ip = client_address[0]
				client_port = client_address[1]
				logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"provider":"honeypot","action":"_accept_connections","reason":"RDP connection attempt","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
				
				# Handle the connection in a separate thread
				threading.Thread(target=self._handle_client, args=(client_socket, client_address), daemon=True).start()
			except Exception as e:
				if self.running:  # Only log if server is running
					logger.error(f'"type":["error"],"kind":"event","category":["process"],"provider":"application","action":"_accept_connections","reason":"RDP error accepting connections","outcome":"failure"}},"error":{{"message":"{e}"')

	# Simulate interaction with a client.
	def _handle_client(self, client_socket, client_address):
		try:
			client_ip = client_address[0]
			client_port = client_address[1]

			logger.debug(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"provider":"honeypot","action":"_handle_client","reason":"Simulating RDP handshake","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
			rdp_response = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x1c\x01\x01\x02\x00\x08\x00\x00\x00"
			client_socket.sendall(rdp_response)
			data = client_socket.recv(1024)
			logger.debug(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"provider":"honeypot","action":"_handle_client","reason":"RDP received data","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"provider":"application","action":"_handle_client","reason":"Error handling client","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			client_socket.close()
			logger.info(f'"type":["connection","end"],"kind":"alert","category":["network","intrusion_detection"],"provider":"honeypot","action":"_handle_client","reason":"Socket close","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
