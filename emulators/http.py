import os
import ssl
import json
import socket
import threading
import http.server
import utils.config as config
from socketserver import TCPServer
from urllib.parse import parse_qs, urlunparse, urlparse
from utils.logger import appLogger
from utils.logger import honeyLogger
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Custom request handler to serve only the login page
class LoginPageHandler(http.server.BaseHTTPRequestHandler):
	http_root = "./emulators/http_root"
	default_doc = config.get_service_by_name("http")["default_doc"]

	def log_message(self, format, *args):
		# This method is overridden to do nothing, effectively disabling the log output
		pass

	def set_common_headers(self):
		# Add headers to mimic IIS 10.0
		self.send_header("Server", config.get_service_by_name("http")["server_header"])

	def version_string(self):
		# Override the server software version
		return config.get_service_by_name("http")["server_header"]

	def sys_version(self):
		# Suppress the Python version in the header
		return ""

	def get_full_url(self):
		# Determine the scheme from headers (assume "http" or "https")
		protocol = "https" if self.headers.get("X-Forwarded-Proto", "http") == "https" else "http"

		# Get the host (domain) from the Host header
		host = self.headers.get("Host", "localhost")

		# Extract path, query, and fragment components
		parsed_path = urlparse(self.path)

		# Build the full URL
		full_url = urlunparse((
			protocol,
			host,
			parsed_path.path,
			parsed_path.params,
			parsed_path.query,
			parsed_path.fragment
		))

		return json.dumps(full_url)

	def is_authenticated(self):
		# Check for an (intentionally-insecure) authentication cookie
		cookie_header = self.headers.get("Cookie")
		if cookie_header:
			cookie = SimpleCookie(cookie_header)
			if "session" in cookie and cookie["session"].value == "authenticated":
				return True
		return False

	def send_error_page(self, response_code: int):
		honeyLogger.info(f'"type":["connection","denied"],"kind":"alert","category":["web","network","intrusion_detection"],"dataset":"faitour.honeypot","action":"http_get","reason":"HTTP GET Request","outcome":"failure"}},"source":{{"ip":"{self.client_address[0]}","port":{self.client_address[1]}}},"destination":{{"ip":"{self.server.server_address[0]}","port":{self.server.server_address[1]}}},"http":{{"request":{{"method":"GET"}},"response":{{"status_code":{response_code}}}}},"url":{{"full":{self.get_full_url()},"path":{json.dumps(self.path)}')
		self.send_response(response_code)
		self.send_header("Content-type", "text/html")
		#self.set_common_headers()
		self.send_header("Server", config.get_service_by_name("http")["server_header"])
		self.end_headers()
		error_page_path = f"{self.http_root}/error_pages/{response_code}.html"

		try:
			with open(error_page_path, "r") as file:
				content = file.read()
				self.wfile.write(content.encode("utf-8"))
		except FileNotFoundError:
			# Fallback if custom error page is missing
			if response_code == 401:
				self.wfile.write(b"401 Unauthorized")
			if response_code == 404:
				self.wfile.write(b"403 Forbidden")
			if response_code == 404:
				self.wfile.write(b"404 Not Found")

	def serve_page(self, method, status_code, path):
		honeyLogger.info(f'"type":["connection","allowed","info"],"kind":"alert","category":["web","network","intrusion_detection"],"dataset":"faitour.honeypot","action":"http_get","reason":"HTTP {method} Request","outcome":"success"}},"source":{{"ip":"{self.client_address[0]}","port":{self.client_address[1]}}},"destination":{{"ip":"{self.server.server_address[0]}","port":{self.server.server_address[1]}}},"http":{{"request":{{"method":"{method}"}},"response":{{"status_code":{status_code}}}}},"url":{{"full":{self.get_full_url()},"path":{json.dumps(path)}')
		self.send_response(status_code)
		self.send_header("Content-type", "text/html")
		if path == "/logout.html":
			self.send_header("Set-Cookie", "session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly")
		self.send_header("Server", config.get_service_by_name("http")["server_header"])
		self.end_headers()
		with open(f"{self.http_root}{path}", "r") as file:
			self.wfile.write(file.read().encode("utf-8"))

	def do_GET(self):
		if self.path.endswith("README.md"):
			# Explicitly return 404 for any README.md files
			self.send_error_page(404)
		elif os.path.exists(f"{self.http_root}/{self.path}"):
			if os.path.isfile(f"{self.http_root}/{self.path}"):
				# Check to see if this is a protected document
				with open(f"{self.http_root}/{self.path}", "r") as file:
					if "PROTECTED" in file.readline().strip():
						protected = True
					else:
						protected = False

				if protected:
					if self.is_authenticated():
						# Protected but authenticated. Serve the page.
						self.serve_page("GET", 200, self.path)
					else:
						# Protected but not authenticated.
						self.send_error_page(401)
				else:
					# Not protected. Serve the page.
					self.serve_page("GET", 200, self.path)
			else:
				# Requested path was a directory. See if there is a default document
				if os.path.exists(f"{self.http_root}/{self.path}/{self.default_doc}"):
					# Check to see if this should be a protected document
					with open(f"{self.http_root}/{self.path}/{self.default_doc}", "r") as file:
						if "PROTECTED" in file.readline().strip():
							protected = True
						else:
							protected = False

					if protected:
						if self.is_authenticated():
							# Protected but authenticated. Serve the page.
							self.serve_page("GET", 200, f"{self.path}/{self.default_doc}")
						else:
							# Protected but not authenticated.
							self.send_error_page(401)
					else:
						# Not protected. Serve the page.
						self.serve_page("GET", 200, f"{self.path}/{self.default_doc}")
				else:
					# Page does not exist.
					self.send_error_page(404)
		else:
			# If it's any other path, return 404
			self.send_error_page(404)

	def do_POST(self):
		# Parse the content type and content length
		content_type = self.headers.get("Content-Type")
		content_length = int(self.headers.get("Content-Length", 0))

		# Read the form data
		try:
			post_data = self.rfile.read(content_length)
		except Exception as e:
			appLogger.error(f'"type":["error"],"kind":"event","category":["web","process"],"dataset":"faitour.application","action":"do_POST","reason":"HTTP POST error","outcome":"failure"}},"error":{{"message":"{e}"')

		# Parse the form data
		if content_type == "application/x-www-form-urlencoded":
			form_data = parse_qs(post_data.decode("utf-8"))
		else:
			# Handle other content types, if needed
			form_data = {}

		# Extract username and password from form data
		username = form_data.get("username", [""])[0]
		password = form_data.get("password", [""])[0]

		# Validate the credentials (you can add your own logic here)
		if username == config.get_service_by_name("http")["username"] and password == config.get_service_by_name("http")["password"]:
			honeyLogger.info(f'"type":["allowed"],"kind":"alert","category":["web","network","authentication","intrusion_detection"],"dataset":"faitour.honeypot","action":"login","reason":"User login success","outcome":"success"}},"source":{{"ip":"{self.client_address[0]}","port":{self.client_address[1]}}},"destination":{{"ip":"{self.server.server_address[0]}","port":{self.server.server_address[1]}}},"http":{{"request":{{"method":"POST"}},"response":{{"status_code":200}}}},"url":{{"full":{self.get_full_url()},"path":{json.dumps(self.path)}}},"user":{{"name":"{username}","password":"{password}"')
			cookie = SimpleCookie()
			cookie["session"] = "authenticated"  # This is intentionally insecure
			cookie["session"]["httponly"] = True
			cookie["session"]["max-age"] = 3600  # 1 hour
			self.send_response(200)
			self.send_header("Server", config.get_service_by_name("http")["server_header"])
			self.send_header("Content-type", "text/html")
			for morsel in cookie.values():
				self.send_header("Set-Cookie", morsel.OutputString())
			self.end_headers()
			with open(f"{self.http_root}/index.html", "r") as file:
				self.wfile.write(file.read().encode("utf-8"))
		else:
			honeyLogger.error(f'"type":["denied"],"kind":"alert","category":["web","network","authentication","intrusion_detection"],"dataset":"faitour.honeypot","action":"login_fail","reason":"User login failed","outcome":"failure"}},"source":{{"ip":"{self.client_address[0]}","port":{self.client_address[1]}}},"destination":{{"ip":"{self.server.server_address[0]}","port":{self.server.server_address[1]}}},"http":{{"request":{{"method":"POST"}},"response":{{"status_code":401}}}},"url":{{"full":{self.get_full_url()},"path":{json.dumps(self.path)}}},"user":{{"name":"{username}","password":"{password}"')
			self.send_error_page(401)

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
			appLogger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start_http","reason":"HTTP server emulator is starting on http://{self.host_ip}:{self.host_port}","outcome":"unknown"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')
			TCPServer.allow_reuse_address = True
			httpd_http = TCPServer((self.host_ip, self.host_port), LoginPageHandler)
			httpd_http.serve_forever()
			appLogger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start_http","reason":"HTTP server emulator has started on http://{self.host_ip}:{self.host_port}","outcome":"success"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')

	def start_https(self):
		if self.https_enabled:
			self.running = True

			# Generate certs if they don't exist
			self.generate_self_signed_cert()

			appLogger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start_http","reason":"HTTPS server emulator is starting on https://{self.host_ip}:{self.https_port}","outcome":"unknown"}},"server":{{"ip":"{self.host_ip}","port":{self.host_port}')
			TCPServer.allow_reuse_address = True
			httpd_https = TCPServer((self.host_ip, self.https_port), LoginPageHandler)

			# Create an SSL context
			context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
			context.load_cert_chain(certfile='./emulators/http_cert.pem', keyfile='./emulators/http_key.pem')

			# Wrap the server socket with the SSL context
			httpd_https.socket = context.wrap_socket(httpd_https.socket, server_side=True)

			httpd_https.serve_forever()
			appLogger.info(f'"type":["start"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"start_http","reason":"HTTPS server emulator has started on https://{self.host_ip}:{self.https_port}","outcome":"success"}},"server":{{"ip":"{self.host_ip}","port":{self.https_port}')

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
			appLogger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop_servers","reason":"HTTP server emulator is stopping","outcome":"unknown"')
			self.httpd_http.shutdown()
			self.httpd_http.server_close()
			self.httpd_http = None
			appLogger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop_servers","reason":"HTTP server emulator has stopped","outcome":"success"')

		# Stop the HTTPS server if it's running
		if self.httpd_https:
			appLogger.info(f'"type":["info"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop_servers","reason":"HTTPS server emulator is stopping","outcome":"unknown"')
			self.httpd_https.shutdown()
			self.httpd_https.server_close()
			self.httpd_https = None
			appLogger.info(f'"type":["end"],"kind":"event","category":["process"],"dataset":"faitour.application","action":"stop_servers","reason":"HTTPS server emulator has stopped","outcome":"success"')

	def generate_self_signed_cert(self):
		# Set cert and key paths
		cert_path="./emulators/http_cert.pem"
		key_path="./emulators/http_key.pem"

		# Check if the certificate and key files already exist
		if os.path.exists(cert_path) and os.path.exists(key_path):
			appLogger.debug(f'"type":["info"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"generate_self_signed_cert","reason":"HTTP certificate and key already exist","outcome":"success"')
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

		appLogger.debug(f'"type":["creation"],"kind":"event","category":["configuration"],"dataset":"faitour.application","action":"generate_self_signed_cert","reason":"HTTPS Self-signed certificate and key generated","outcome":"success"')
