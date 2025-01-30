# Faitour 2.0

**fai*tour ('fei ter)**  
n. Archaic  
[1300-1350] Middle English - A charlatan or imposter

![Faitour 2](logo_wide.png)

## About

Faitour 2 is a complete rewrite of [MakoWish/Faitour](https://github.com/MakoWish/Faitour). which was originally forked from [eightus/Cyder](https://github.com/eightus/Cyder), so I must first give credit to that project for the inspiration. The issue with the original Faitour was that packets to any real services would be intercepted and not properly forwarded, so the services were rendered useless. This defeated the purpose of working alongside OpenCanary as it blocked all access to OpenCanary's enabled services. For this reason, I decided to start from scratch and try to create my own honeypot with some fully-functional services and detailed logging. 

The idea behind this project was to not only spoof services to NMAP scans, but also log all access attempts in a format that follows the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html). This will make parsing the logs much easier for ingestion into Elasticsearch. Once I feel this project has matured a bit more, I will work on an [Elastic integration](https://www.elastic.co/integrations/data-integrations) to take all the work out of ingesting these logs, as well as creating Elastic Security alerts based on observed activity.

## Supported Operating Systems

This project was built on, and has been tested on, Ubuntu 24.04 LTS. Other operating systems **_may_** work , but I have not tested any others.

## Installation

### Download

The ultimate location is up to you, but I typically install optional software to `/opt`, so I would navigate there first, then clone the project.

```bash
cd /opt
sudo git clone https://github.com/MakoWish/Faitour.git
```

### Setup

In an attempt to make installation easier, I have provided an install script that should help to get you up and running. This install script will ensure all dependencies are installed and a `systemd` service is created. To install, simple run as root:

```bash
sudo ./install.py
```

### Configuration

#### Required Network and Logging Details

After installing, you will need to change the configurations before starting the service. The configuration file is located at:

`./config.yml`

You **_must_** change the default settings under `network`, or Faitour will fail to start. Ensure the adapter details match what is on your host.

Optionally, configure logging to fit your needs. By default, both file and stdout logging are enabled, but you may turn either or both off. If running as a `systemd` service (default), the stdout logging will be written to the systemd journal.

Here is a snippet from the default `config.yml`:

```yaml
---
description: Application configuration file for Faitour 2.0

network:
  adapter:
    name: change_me
    ip: 10.0.0.0
    mac: 00:11:22:33:44:55

logging:
  level: DEBUG    # DEBUG, INFO, WARN, ERROR, CRITICAL
  name: faitour
  stdout:
    enabled: True
  file:
    enabled: True
    path: /var/log/faitour/
    size: 10000000
    count: 10
```

#### Operating System Fingerprint

Beyond the basic network and logging configuration, you will also see details for the operating system fingerprint in your config file. By default, the operating system is set to Microsoft Windows Server 2008 R2. If you would like to change fingerprint, please reference the NMAP fingerprints databases. Note that the majority of these fingerprints contain regex patterns. You should replace those regex patterns with data that would not only be matched by those patterns, but also matches the service you are attempting to spoof.

Operating System Fingerprints can be found at: https://svn.nmap.org/nmap/nmap-os-db

#### Service Emulators

Several services are emulated that allow real interaction like FTP, Telnet, SSH, and HTTP/S (these are enabled by default) as well as others that you may enable. These services allow you to customize the port they run on, usernames:passwords that grant access to those services, and more. Many of these services provide file system access that you may customize to your liking. This may be a custom web page or pages in `./emulators/web_root`, or files in `./emulators/ftp_root` or `./emulators/telnet_root`.

Service Fingerprints can be found at: https://svn.nmap.org/nmap/nmap-service-probes

**_IMPORTANT_**: 

1. If you are going to enable the SSH service, you will need to first change the port your actually SSH is running on. Choose an obscure port number that will not show up on the typical NMAP scan. Ideally, disable SSH and rely on console access only.
2. If setting up a custom web page, ensure the web form attributes remain the same.
3. If using HTTPS, be sure to update the `tls` settings in `config.yml` to use a more believable name than the default "foo.example.org". Optionally, you may use your own custom certificate. The key must be placed in `./emulators/http_key.pem`, and the cert/chain must be placed in `./emulator/http_cert.pem`.
    1. If you change the `tls` settings in `config.yml`, be sure to delete any `*.pem` files in `./emulators` so new ones will be generated.

### Starting

To start Faitour as systemd service, enable and start the service. You may optionally follow the journal logs to ensure the service started without issue:

```bash
# Enable and start the service
sudo systemctl enable faitour.service
sudo systemctl start faitour.service

# Optionally follow the journal logs
sudo journalctl -fu faitour.service

# Or tail the file logs
sudo tail -f /var/log/faitour/faitour
```

To start Faitour manually, simply execute with Python as root.

```bash
sudo ./faitour.py
```

### Testing

Once Faitour has been started, be sure to run an NMAP scan from another machine to ensure that everything is working as expected. 

`nmap -sS -sV -O <ip address>`

## Elastic Integration

I have included some resources within the `elastic` folder to help integrate your Faitour logs with Elastic for monitoring and alerting on honeypot activity. Please review the Elastic [README.md](./elastic/README.md) for details on installing those resources.

## Questions and Discussions

If you have any questions about installation, or would just like to discuss the project, please start a [discussion](../../discussions) to get the conversation going.

## Contributing

If you would like to contribute to this project, please first open an issue with your idea so we can discuss it.

## To Do

* Change services like RPC, RDP, MSSQL, MySQL, and PostgreSQL to be less of emulators and more just fingerprint spoofers.
* Create and submit Elastic Agent integration for official release.
* Create sample Elastic Security detection rules for alerting on honeypot triggers.
