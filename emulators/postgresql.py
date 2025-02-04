from utils.logger import logger
import utils.config as config
import socket
import threading

class PostgreSQLServer:
	def __init__(self):
		self.running = False
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("postgresql")["port"]
		self.server_socket = None

	# Starts the emulated PostgreSQL server.
	def start(self):
		if self.running:
			logger.info(f'"type":["info","start"],"kind":"event","category":["process"],"provider":"application","action":"start","reason":"PostgreSQL server emulator is already running","outcome":"success"')
			return

		try:
			logger.info(f'"type":["start"],"kind":"event","category":["process"],"provider":"application","action":"start","reason":"PostgreSQL server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"success"')
			self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server_socket.bind((self.host_ip, self.host_port))
			self.server_socket.listen(5)
			self.running = True

			threading.Thread(target=self._accept_connections, daemon=True).start()
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"provider":"application","action":"start","reason":"PostgreSQL server emulatore failed to start","outcome":"failure"}},"error":{{"message":"{e}"}}')

	# Stops the emulated PostgreSQL server.
	def stop(self):
		if not self.running:
			return

		self.running = False
		logger.info(f'"type":["end"],"kind":"event","category":["process"],"provider":"application","action":"stop","reason":"PostgreSQL server emulator is stopping","outcome":"success"')
		if self.server_socket:
			self.server_socket.close()
			self.server_socket = None
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"provider":"application","action":"stop","reason":"PostgreSQL server emulator has stopped","outcome":"success"')

	# Handles incoming client connections.
	def _accept_connections(self):
		while self.running:
			try:
				client_socket, address = self.server_socket.accept()
				client_ip = address[0]
				client_port = address[1]
				logger.info(	f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"provider":"honeypot","action":"_accept_connections","reason":"Connection received","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
				threading.Thread(target=self._handle_client, args=(client_socket, address), daemon=True).start()
			except Exception as e:
				if self.running:  # Only log errors if the server is running
					logger.error(f'"type":["error"],"kind":"event","category":["network"],"provider":"application","action":"_accept_connections","reason":"Error accepting connections","outcome":"failure"}},"error":{{"message":"{e}"')

	# Handles communication with a connected client.
	def _handle_client(self, client_socket, address):
		try:
			client_ip = address[0]
			client_port = address[1]

			# Send a PostgreSQL server version string to mimic the real server
			client_socket.send(b"\x52\x00\x00\x00\x0d\x00\x03\x00\x00\x5c\x00\x00\x00\x00")  # Startup Response

			while self.running:
				data = client_socket.recv(1024)
				if not data:
					break

				logger.info(f'"type":["connection","allowed","end"],"kind":"alert","category":["network","intrusion_detection"],"provider":"honeypot","action":"_handle_client","reason":"Received data {data.hex()}","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')

				# Respond with a dummy authentication request (PostgreSQL handshake)
				response = b"R" + b"\x00\x00\x00\x08" + b"\x00\x00\x00\x00"
				client_socket.send(response)

		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["network"],"provider":"application","action":"_handle_client","reason":"Error accepting connection","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			client_socket.close()
			logger.info(f'"type":["connection","allowed","end"],"kind":"alert","category":["network","intrusion_detection"],"provider":"honeypot","action":"_handle_client","reason":"Connection closed","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
