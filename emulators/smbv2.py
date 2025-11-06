import codecs
import socket
import threading
import utils.config as config
from utils.logger import appLogger
from utils.logger import honeyLogger

class SMBv2Server:
	def __init__(self):
		self.running = False
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("smb")["port"]
		self.directory_structure = {
			"": ["Users", "Program Files", "Windows"],
			"Users": ["Admin", "Guest"],
			"Users/Admin": ["Documents", "Downloads", "Desktop"],
			"Users/Admin/Documents": ["report.docx", "presentation.pptx"],
			"Users/Admin/Downloads": ["setup.exe", "readme.txt"],
			"Users/Admin/Desktop": ["shortcut.lnk"],
			"Program Files": ["App1", "App2"],
			"Program Files/App1": ["app1.exe", "config.cfg"],
			"Program Files/App2": ["app2.exe", "data.dat"],
			"Windows": ["System32", "Temp"],
			"Windows/System32": ["kernel32.dll", "cmd.exe"],
			"Windows/Temp": []
		}

	def start(self):
		appLogger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"SMBv2 server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"unknown"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')
		self.running = True
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable port reuse
		self.server_socket.bind((self.host_ip, self.host_port))
		self.server_socket.listen(5)
		appLogger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"SMBv2 server emulator has started on {self.host_ip}:{self.host_port}","outcome":"success"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')

		while self.running:
			try:
				client_socket, address = self.server_socket.accept()
				client_ip = address[0]
				client_port = address[1]
				honeyLogger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"start","reason":"SMBv2 connection started","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
				threading.Thread(target=self.handle_client, args=(client_socket, address)).start()
				honeyLogger.info(f'"type":["connection","end"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"start","reason":"SMBv2 connection ended","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
			except Exception as e:
				appLogger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start","reason":"Error accepting SMBv2 connection","outcome":"failure"}},"error":{{"message":"{e}"')

	def stop(self):
		if not self.running:
			return

		try:
			appLogger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"SMBv2 server emulator is stopping","outcome":"unknown"')
			if self.running:
				self.server_socket.close()
				self.server_socket = None
			self.running = False
			appLogger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"SMBv2 server emulator has stopped","outcome":"success"')
		except Exception as e:
			appLogger.error(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"handle_packet","reason":"SMBv2 failed to stop server","outcome":"failure"}},"error":{{"message":"{e}"')

	def handle_client(self, client_socket, address):
		try:
			# Get client IP and port from address
			client_ip = address[0]
			client_port = address[1]

			while self.running:
				# If initial data does not start with 0xFF, this is likely an NMAP service fingerprinting scan
				data = client_socket.recv(1024)
				if not data or data[0] != 0xff:
					honeyLogger.warning(f'"type":["connection","start"],"kind":"event","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"handle_client","reason":"Initial client data appears to be SMB service fingerprinting attempt","outcome":"unknown"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')

					# Send out spoofed fingerprint
					binary_fingerprint = codecs.decode(config.get_service_by_name("smb")["fingerprint"], "unicode_escape").encode("latin1")
					client_socket.sendall(binary_fingerprint)

				#data = client_socket.recv(1024)  # Receive raw bytes
				if not data:
					break
				try:
					# Attempt to decode as UTF-8 for basic text-based commands
					decoded_data = data.decode("utf-8").strip()
					response = self.process_request(decoded_data)
				except UnicodeDecodeError:
					# Handle cases where the data is not valid UTF-8
					response = "Received unsupported binary data.\n"
				client_socket.sendall(response.encode("utf-8"))
		except Exception as e:
			appLogger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"handle_client","reason":"Error handling client","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			client_socket.close()

	def process_request(self, request):
		honeyLogger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"process_request","reason":"Received request","outcome":"success"')
		parts = request.split()

		if len(parts) == 0:
			return "Invalid command.\n"

		command = parts[0].lower()

		if command == "list":
			path = parts[1] if len(parts) > 1 else ""
			if path in self.directory_structure:
				return "\n".join(self.directory_structure[path]) + "\n"
			else:
				return "Path not found.\n"

		elif command == "quit":
			return "Goodbye.\n"

		else:
			return "Unknown command.\n"
