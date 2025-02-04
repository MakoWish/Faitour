import socket
import threading
import utils.config as config
from utils.logger import logger

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
		logger.info(f'"type":["start"],"kind":"event","category":["process"],"provider":"application","action":"start","reason":"SMBv2 server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"success"')
		self.running = True
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_socket.bind((self.host_ip, self.host_port))
		self.server_socket.listen(5)

		while self.running:
			try:
				client_socket, client_address = self.server_socket.accept()
				client_ip = client_address[0]
				client_port = client_address[1]
				logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"provider":"honeypot","action":"start","reason":"SMBv2 connection","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
				threading.Thread(target=self.handle_client, args=(client_socket,)).start()
			except Exception as e:
				logger.error(f'"type":["error"],"kind":"event","category":["process"],"provider":"application","action":"start","reason":"Error accepting SMBv2 connection","outcome":"failure"}},"error":{{"message":"{e}"')

	def stop(self):
		logger.info(f'"type":["end"],"kind":"event","category":["process"],"provider":"application","action":"stop","reason":"SMBv2 server emulator is stopping","outcome":"success"')
		if self.running:
			self.running = False
			self.server_socket.close()
		logger.info(f'"type":["end"],"kind":"event","category":["process"],"provider":"application","action":"stop","reason":"SMBv2 server emulator has stopped","outcome":"success"')

	def handle_client(self, client_socket):
		try:
			client_socket.sendall(b"Welcome to SMBv2 Server\n")
			while self.running:
				data = client_socket.recv(1024)  # Receive raw bytes
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
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"provider":"application","action":"handle_client","reason":"Error handling client","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			client_socket.close()

	def process_request(self, request):
		logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"provider":"honeypot","action":"process_request","reason":"Received request","outcome":"success"')
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
