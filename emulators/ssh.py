import os
import json
import codecs
import socket
import select
import threading
import traceback
import utils.config as config
from utils.logger import logger
from paramiko import ServerInterface, Transport, AUTH_SUCCESSFUL, OPEN_SUCCEEDED, SFTPServer
from paramiko.sftp_server import SFTPServerInterface, SFTPAttributes
from paramiko import RSAKey
#from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class SimpleSSHServer(ServerInterface):
	USERNAME = config.get_service_by_name("ssh")["username"]
	PASSWORD = config.get_service_by_name("ssh")["password"]
	ROOT_DIR = os.path.abspath("./emulators/ssh_root")

	def __init__(self, client_ip=None, client_port=None):
		self.event = threading.Event()
		self.client_ip = client_ip
		self.client_port = client_port

	def check_auth_password(self, username, password):
		# Validate the username and password
		if username == self.USERNAME and password == self.PASSWORD:
			logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","authentication","intrusion_detection"],"dataset":"faitour.honeypot","action":"check_auth_password","reason":"SSH authentication successful","outcome":"success"}},"user":{{"name":"{username}","password":"{password}"}},"source":{{"ip":"{self.client_ip}","port":{self.client_port}')
			return AUTH_SUCCESSFUL
		logger.warning(f'"type":["connection","denied"],"kind":"alert","category":["network","authentication","intrusion_detection"],"dataset":"faitour.honeypot","action":"check_auth_password","reason":"SSH authentication failed","outcome":"failure"}},"user":{{"name":"{username}","password":"{password}"}},"source":{{"ip":"{self.client_ip}","port":{self.client_port}')
		return None

	def check_channel_request(self, kind, chanid):
		if kind == "session":
			return OPEN_SUCCEEDED
		return None

	def get_allowed_auths(self, username):
		return "password"

	def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
		client_ip, client_port = channel.getpeername()
		logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"check_channel_pty_request","reason":"SSH PTY requested","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}')
		return True

	def check_channel_shell_request(self, channel):
		client_ip, client_port = channel.getpeername()
		logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"check_channel_shell_request","reason":"SSH shell requested","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}')
		self.event.set()
		return True

	def check_channel_subsystem_request(self, channel, name):
		if name == "sftp":
			client_ip, client_port = channel.getpeername()
			logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"check_channel_subsystem_request","reason":"SFTP subsystem requested","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}')
			return True
		return False

	def open_sftp_server(self, channel):
		client_ip, client_port = channel.getpeername()
		logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"open_sftp_server","reason":"SFTP server opening","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}')
		return SimpleSFTPServer(channel)

class SimpleSFTPServer(SFTPServer):
	def __init__(self, channel):
		super().__init__(channel)

	def _realpath(self, path):
		real_path = os.path.abspath(os.path.join(SimpleSSHServer.ROOT_DIR, path.lstrip("/")))
		if not real_path.startswith(SimpleSSHServer.ROOT_DIR):
			logger.warning(f'"type":["connection","denied"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"_realpath","reason":"Access denied to path: {path}","outcome":"success"')
		return real_path

	def list_folder(self, path):
		real_path = self._realpath(path)
		try:
			files = os.listdir(real_path)
			attributes = []
			for file in files:
				file_path = os.path.join(real_path, file)
				stats = os.stat(file_path)
				attributes.append(SFTPAttributes.from_stat(stats, file))
			return attributes
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"list_folder","reason":"Error listing folder {path}","outcome":"failure"}},"error":{{"message":"{e}"')
			raise

	def stat(self, path):
		try:
			real_path = self._realpath(path)
			stats = os.stat(real_path)
			return SFTPAttributes.from_stat(stats)
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stat","reason":"Error stat\'ing path {path}","outcome":"failure"}},"error":{{"message":"{e}"')
			raise

	def open(self, path, flags, attr):
		try:
			real_path = self._realpath(path)
			mode = {os.O_RDONLY: "rb", os.O_WRONLY: "wb"}.get(flags & (os.O_RDONLY | os.O_WRONLY))
			return open(real_path, mode)
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"open","reason":"ErrorError opening file {path}","outcome":"failure"}},"error":{{"message":"{e}"')
			raise

class SSHServer:
	bash_hostname = config.get_service_by_name("ssh")["hostname"]
	bash_username = config.get_service_by_name("ssh")["username"]

	def __init__(self):
		self.running = False
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("ssh")["port"]
		self.server_socket = None
		self.transport = None
		self.thread = None

	def start(self):
		if self.thread is not None and self.thread.is_alive():
			self.running = True
			return

		self.host_key = self.get_ssh_key()
		self.thread = threading.Thread(target=self.run_server)
		self.thread.start()
		self.running = True

	def _looks_like_ssh_banner(self, sock, peek_timeout=1.0):
		try:
			r, _, _ = select.select([sock], [], [], peek_timeout)
			if not r:
				return False  # nothing sent (likely a bare TCP probe)
			data = sock.recv(8, socket.MSG_PEEK)  # don't consume
			return data.startswith(b"SSH-")
		except Exception:
			return False

	def run_server(self):
		logger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"run_server","reason":"SSH server emulator is starting on {self.host_ip}:{self.host_port}","outcome":"success"')
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of port
		self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
		self.server_socket.bind((self.host_ip, self.host_port))
		self.server_socket.listen(100)
		self.server_socket.settimeout(1)  # Set a timeout to avoid blocking indefinitely

		while self.running:
			try:
				client_socket, client_address = self.server_socket.accept()
			except socket.timeout:
				continue	# Loop back and keep accepting
			except OSError as e:
				if not self.running:
					break
				logger.exception(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"run_server","reason":"OSError exception on connection: {e}","outcome":"failure"')
				continue
			except Exception as e:
				logger.exception(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"run_server","reason":"Listener unexpected exception: {e}","outcome":"failure"')

			# Pass off each connection to its own thread to prevent blocking
			t = threading.Thread(
				target=self._handle_client,
				args=(client_socket, client_address),
				daemon=True
			)
			t.start()

	def _handle_client(self, client_socket, client_address):
		client_ip, client_port = client_address
		transport = None
		try:
			# If the client doesn't speak SSH, it might just be a TCP port check
			if not self._looks_like_ssh_banner(client_socket, peek_timeout=1.0):
				logger.debug(f'"type":["connection","end"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"run_server","reason":"Client does not speak SSH","outcome":"failure"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
				return

			logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"run_server","reason":"SSH server accepted connection","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
			transport = Transport(client_socket)
			transport.add_server_key(self.host_key)

			# Send our custom version string from config
			transport.local_version = config.get_service_by_name("ssh")["fingerprint"].strip()

			server = SimpleSSHServer(client_ip, client_port)
			transport.start_server(server=server)

			# Wait for a channel with a bounded timeout
			channel = transport.accept(timeout=10.0)
			if channel is None:
				# No channel. Clean up this Transport and try again
				logger.warning(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"run_server","reason":"No channel established. Closing...","outcome":"failure"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
				transport.close()
				return

			# Bound channel I/O operations
			channel.settimeout(300.0)  # idle session timeout

			server.event.wait(10)
			if not server.event.is_set():
				logger.warning(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"run_server","reason":"SSH no shell request received, closing channel","outcome":"failure"')
				channel.close()
				transport.close()
				return

			self.handle_shell(channel)

		except Exception as e:
			logger.exception(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"run_server","reason":"Client handler error: {e}","outcome":"failure"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
		finally:
			try:
				if transport is not None:
					transport.close()
			except Exception:
				logger.exception(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"run_server","reason":"Error closing transport","outcome":"failure"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
			try:
				client_socket.close()
			except Exception:
				logger.exception(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"run_server","reason":"Error closing client socket","outcome":"failure"')
				logger.exception('Error closing client socket')

	def handle_shell(self, channel):
		try:
			client_ip, client_port = channel.getpeername()
			logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"handle_shell","reason":"SSH connection","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')

			# Send the login banner from config
			ssh_banner = codecs.decode(config.get_service_by_name("ssh")["login_banner"], "unicode_escape").encode("latin1")
			channel.send(ssh_banner)

			buffer = ""
			channel.send(f"{self.bash_username}@{self.bash_hostname}:$ ")  # Send initial prompt
			while True:
				data = channel.recv(1024).decode("utf-8")
				if not data:
					break

				for char in data:
					if char in ['\r', '\n']:
						command = buffer.strip()
						buffer = ""

						logger.info(f'"type":["connection","allowed","start"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"faitour.honeypot","action":"handle_shell","reason":"SSH client: {json.dumps(command)[1:-1]}","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"destination":{{"ip":"{self.host_ip}","port":{self.host_port}')
						if command.lower() in ["exit", "quit"]:
							channel.send("\r\nGoodbye!\r\n")
							return
						elif command:
							try:
								# Change directory to ROOT_DIR to ensure isolation
								os.chdir(f"{SimpleSSHServer.ROOT_DIR}/home/admin")

								if command.startswith("cd "):
									new_dir = command[3:]
									new_path = os.path.abspath(os.path.join(SimpleSSHServer.ROOT_DIR, new_dir))
									if new_path.startswith(SimpleSSHServer.ROOT_DIR):
										os.chdir(new_path)
										channel.send("\r\n")
									else:
										channel.send("\r\nAccess denied")
								elif command == "pwd":
									relative_path = os.path.relpath(os.getcwd(), SimpleSSHServer.ROOT_DIR)
									channel.send(f"\r\n/{relative_path if relative_path != '.' else ''}")
								else:
									import subprocess

									process = subprocess.Popen(
										command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
									)
									stdout, stderr = process.communicate()
									if stdout:
										channel.send(f"\r\n{stdout.strip()}")
									if stderr:
										channel.send(f"\r\n{stderr.strip()}")
							except Exception as e:
								channel.send(f"\r\nError executing command: {e}")
						channel.send(f"\r\n{self.bash_username}@{self.bash_hostname}:$ ")  # Send prompt after processing command
					else:
						buffer += char
						channel.send(char)  # Echo back typed character
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"handle_packet","reason":"SSH shell handling error","outcome":"failure"}},"error":{{"message":"{e}"')
		finally:
			channel.close()

	# Stops the SSH server.
	def stop(self):
		logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"SSH server emulator is stopping","outcome":"success"')
		self.running = False
		if self.server_socket:
			self.server_socket.close()  # Interrupt the blocking accept() call
			self.server_socket = None
		if self.transport:
			self.transport.close()
			self.transport = None
		if self.thread:
			self.thread.join()  # Wait for the server thread to finish
			self.thread = None

		logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop","reason":"SSH server emulator has stopped","outcome":"success"')

	# Generates a self-signed certificate and private key if they do not already exist.
	def get_ssh_key(self):
		key_path = "./emulators/ssh_key"

		if not os.path.exists(key_path):
			logger.info(f'"type":["info","creation"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"get_ssh_key","reason":"Generating new SSH RSA key {key_path}","outcome":"success"')
			# Generate a new RSA key
			key = RSAKey.generate(2048)
			key.write_private_key_file(key_path)
		else:
			# Read the existing key from the file
			logger.debug(f'"type":["info","creation"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"get_ssh_key","reason":"RSA key {key_path} already exists","outcome":"success"')
			key = RSAKey(filename=key_path)

		return key
