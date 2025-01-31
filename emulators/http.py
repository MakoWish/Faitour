import os
import ssl
import socket
import threading
import http.server
import utils.config as config
from socketserver import TCPServer
from urllib.parse import parse_qs
from utils.logger import logger
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Custom request handler to serve only the login page
class LoginPageHandler(http.server.BaseHTTPRequestHandler):
	def log_message(self, format, *args):
		# This method is overridden to do nothing, effectively disabling the log output
		pass

	def log_client_ip(self):
		client_ip, client_port = self.client_address
		logger.info(f'"type":["connection","start","allowed"],"kind":"alert","category":["network","intrusion_detection"],"dataset":"honeypot","action":"client_connect","reason":"HTTP connection established","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}')

	def set_common_headers(self):
		self.send_header("Server", config.get_service_by_name("http")["server_header"])

	def version_string(self):
		return config.get_service_by_name("http")["server_header"]

	def sys_version(self):
		# Suppress the Python version in the header
		return ""

	def do_GET(self):
		self.log_client_ip()  # Log the client's IP and port
		if self.path == "/":
			# Serve the login page
			self.send_response(200)
			self.set_common_headers()  # Add headers from config
			self.send_header("Content-type", "text/html")
			self.end_headers()

			# Serve the login HTML page
			with open("./emulators/web_root/login.html", "r") as file:
				self.wfile.write(file.read().encode("utf-8"))
		else:
			# If it's any other path, return 404
			self.send_response(404)
			self.set_common_headers()  # Add headers from config
			self.send_header("Content-type", "text/html")
			self.end_headers()
			self.wfile.write(b"404 Not Found")

	def do_POST(self):
		self.log_client_ip()  # Log the client's IP and port
		# Parse the content type and content length
		content_type = self.headers.get("Content-Type")
		content_length = int(self.headers.get("Content-Length", 0))

		# Read the form data
		try:
			post_data = self.rfile.read(content_length)
		except Exception as e:
			logger.error(f'"type":["error"],"kind":"event","category":["process"],"dataset":"application","action":"do_POST","reason":"HTTP POST error","outcome":"failure"}},"error":{{"message":"{e}"')

		# Parse the form data
		if content_type == "application/x-www-form-urlencoded":
			form_data = parse_qs(post_data.decode("utf-8"))
		else:
			# Handle other content types, if needed
			form_data = {}

		# Extract username and password from form data
		username = form_data.get("username", [""])[0]
		password = form_data.get("password", [""])[0]

		client_ip, client_port = self.client_address

		# Validate the credentials
		if username == config.get_service_by_name("http")["username"] and password == config.get_service_by_name("http")["password"]:
			logger.info(f'"type":["user","connection","allowed"],"kind":"alert","category":["network","authentication","intrusion_detection"],"dataset":"honeypot","action":"do_POST","reason":"HTTP login success","outcome":"success"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"user":{{"name":"{username}","password":"{password}"')
			response = "Thank you for tripping my honeypot!"
			self.send_response(200)
		else:
			logger.error(f'"type":["user","connection","denied"],"kind":"alert","category":["network","authentication","intrusion_detection"],"dataset":"honeypot","action":"do_POST","reason":"HTTP login failure","outcome":"failure"}},"source":{{"ip":"{client_ip}","port":{client_port}}},"user":{{"name":"{username}","password":"{password}"')
			response = "Invalid username or password."
			self.send_response(403)

		# Send the response back to the client
		self.set_common_headers()
		self.send_header("Content-type", "text/html")
		self.end_headers()
		self.wfile.write(response.encode("utf-8"))

class WebServer:
	def __init__(self, http_enabled: bool, https_enabled: bool):
		self.running = False
		self.http_enabled = http_enabled
		self.https_enabled = https_enabled
		self.host_ip = config.get_value("network.adapter.ip")
		self.host_port = config.get_service_by_name("http")["port"]
		self.https_port = config.get_service_by_name("https")["port"]
		self.httpd_http = None
		self.httpd_https = None

	def start_http(self):
		if self.http_enabled:
			self.running = True
			logger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"application","action":"start_http","reason":"HTTP server emulator is starting on http://{self.host_ip}:{self.host_port}","outcome":"success"')
			httpd_http = TCPServer((self.host_ip, self.host_port), LoginPageHandler)
			httpd_http.serve_forever()

	def start_https(self):
		if self.https_enabled:
			self.running = True

			# Generate certs if they don't exist
			self.generate_self_signed_cert()

			logger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"application","action":"start_http","reason":"HTTPS server emulator is starting on https://{self.host_ip}:{self.https_port}","outcome":"success"')
			httpd_https = TCPServer((self.host_ip, self.https_port), LoginPageHandler)

			# Create an SSL context
			context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
			context.load_cert_chain(certfile='./emulators/http_cert.pem', keyfile='./emulators/http_key.pem')
			
			# Wrap the server socket with the SSL context
			httpd_https.socket = context.wrap_socket(httpd_https.socket, server_side=True)
			
			httpd_https.serve_forever()

	def start_servers(self):
		if self.http_enabled:
			http_thread = threading.Thread(target=self.start_http)
			http_thread.daemon = True
			http_thread.start()

		if self.https_enabled:
			https_thread = threading.Thread(target=self.start_https)
			https_thread.daemon = True
			https_thread.start()

	def stop_servers(self):
		# Stop the HTTP server if it's running
		if self.httpd_http:
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop_servers","reason":"HTTP server emulator is stopping","outcome":"success"')
			self.httpd_http.shutdown()
			self.httpd_http.server_close()
			self.httpd_http = None
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop_servers","reason":"HTTP server emulator has stopped","outcome":"success"')

		# Stop the HTTPS server if it's running
		if self.httpd_https:
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop_servers","reason":"HTTPS server emulator is stopping","outcome":"success"')
			self.httpd_https.shutdown()
			self.httpd_https.server_close()
			self.httpd_https = None
			logger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"application","action":"stop_servers","reason":"HTTPS server emulator has stopped","outcome":"success"')

	def generate_self_signed_cert(self):
		# Set cert and key paths
		cert_path="./emulators/http_cert.pem"
		key_path="./emulators/http_key.pem"

		# Check if the certificate and key files already exist
		if os.path.exists(cert_path) and os.path.exists(key_path):
			logger.debug(f'"type":["info","access"],"kind":"event","category":["configuration"],"dataset":"application","action":"generate_self_signed_cert","reason":"HTTP certificate and key already exist","outcome":"success"')
			return

		# Generate a private key
		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048
		)

		# Get TLS details from config
		country_name = config.get_value("tls")["country_name"]
		state = config.get_value("tls")["state"]
		locality = config.get_value("tls")["locality"]
		organization = config.get_value("tls")["organization"]
		common_name = config.get_value("tls")["common_name"]

		# Create a self-signed certificate
		subject = issuer = x509.Name([
			x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
			x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
			x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
			x509.NameAttribute(NameOID.COMMON_NAME, common_name),
		])

		certificate = (
			x509.CertificateBuilder()
			.subject_name(subject)
			.issuer_name(issuer)
			.public_key(private_key.public_key())
			.serial_number(x509.random_serial_number())
			.not_valid_before(datetime.utcnow())
			.not_valid_after(datetime.utcnow() + timedelta(days=365))
			.add_extension(
				x509.SubjectAlternativeName([x509.DNSName(common_name)]),
				critical=False,
			)
			.sign(private_key, hashes.SHA256())
		)

		# Save the private key to a file
		with open(key_path, "wb") as key_file:
			key_file.write(
				private_key.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.NoEncryption()
				)
			)

		# Save the certificate to a file
		with open(cert_path, "wb") as cert_file:
			cert_file.write(
				certificate.public_bytes(encoding=serialization.Encoding.PEM)
			)

		logger.debug(f'"type":["info","creation"],"kind":"event","category":["configuration"],"dataset":"application","action":"generate_self_signed_cert","reason":"HTTPS Self-signed certificate and key generated","outcome":"success"')
