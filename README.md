# Faitour 2.0

**fai*tour ('fei ter)**  
n. Archaic  
[1300-1350] Middle English - A charlatan or imposter

![Faitour 2](logo_wide.png)

## About

Faitour 2 is a complete rewrite of [MakoWish/Faitour](https://github.com/MakoWish/Faitour) which was originally forked from [eightus/Cyder](https://github.com/eightus/Cyder), so I must first give credit to that project for the inspiration. The issue with the original Faitour was that packets to any real services would be intercepted and not properly forwarded, so the services were effectively rendered useless outside of spoofing NMAP scans. This defeated the purpose of working alongside OpenCanary as it blocked all access to OpenCanary's enabled services. For this reason, I decided to start from scratch and try to create my own honeypot with some fully-functional services and detailed logging. 

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

In an attempt to make installation easier, I have provided an install script that should help to get you up and running. This install script will ensure all dependencies are installed and a `systemd` service is created. To install, simply run as root:

```bash
sudo ./install.py
```

### Configuration

#### Required Network and Logging Details

After installing, you will need to change the configurations before starting the service. The configuration file is located at:

`./config.yml`

You **_must_** change the default settings under `network`, or Faitour will fail to start. Ensure the adapter details match what is on your host.

Optionally, configure logging to fit your needs. By default, both file and stdout logging are enabled, but you may turn either or both off. If running as a `systemd` service (default), the stdout logging will be written to the systemd journal. If you will be ingesting events into Elastic, file logging is required, and I suggest keeping the default location of `/var/log/faitour`, as the integration I am working on will look to that location by default.

Here is a snippet from the default `config.yml` detailing the required network and logging settings:

```yaml
---
description: Application configuration file for Faitour 2.0

network:
  adapter:
    name: change_me
    ip: 10.0.0.0
    mac: 00:11:22:33:44:55

logging:
  level: INFO    # DEBUG, INFO, WARN, ERROR, CRITICAL
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

Below the basic network and logging configuration, you will also see details for the operating system fingerprint in your config file. By default, the operating system is set to Microsoft Windows Server 2008 R2. If you would like to change the fingerprint, please reference the NMAP fingerprints databases or some tested examples within `./samples/operating_system.txt`.

NMAP's operating system fingerprints database can be found at: https://svn.nmap.org/nmap/nmap-os-db

#### Service Emulators

Several services may be emulated, and some offer real interaction like FTP, Telnet, SSH, and HTTP(S). These services allow you to customize the port they run on, usernames:passwords that grant access to those services, and more. Many of these services provide file system access that you may customize to your liking. This may be a custom web page or pages in `./emulators/web_root`, or files in `./emulators/ftp_root` or `./emulators/telnet_root`. You may adjust the fingerprints to reflect the system type you are trying to emulate. I have provided some examples in `./samples/<service>.txt`. Please see [./samples/README.md](https://github.com/MakoWish/Faitour2/tree/main/samples/README.md) for more details. 

Service Fingerprints can be found at: https://svn.nmap.org/nmap/nmap-service-probes

Note that the majority of these fingerprints contain regex patterns. You should replace those regex patterns with data that would not only be matched by those patterns, but also matches the service you are attempting to spoof.

**_IMPORTANT_**: 

1. If you are going to enable the SSH service, you will need to first change the port your actual SSH service is running on. Choose an obscure port number that will not show up on the typical NMAP scan. Ideally, disable SSH and rely on console access only.
2. If setting up a custom web page, ensure the web form attributes remain the same.
3. If using HTTPS, be sure to update the `tls` settings in `config.yml` to generate a more believable certificate name than the default "foo.example.org". Optionally, you may use your own custom certificate. The key must be placed in `./emulators/http_key.pem`, and the cert/chain must be placed in `./emulator/http_cert.pem`.
    1. If you change the `tls` settings in `config.yml`, be sure to delete any `*.pem` files in `./emulators` so new ones will be generated with your new settings.

### Starting

To start Faitour as a systemd service, enable and start the service. You may optionally follow the journal logs to ensure the service started without issue:

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

If using the default configuration, your results should look something like this:

```bash
┌──(foobar㉿Kali)-[~]
└─$ sudo nmap -sV -sS -T3 -O HoneyTest
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-07 13:55 MST
Nmap scan report for HoneyTest (192.168.200.10)
Host is up (0.014s latency).
rDNS record for 192.168.200.10: HoneyTest.test.lab
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 7.5
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp open  ssl/http     Microsoft IIS httpd 7.5
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 microsoft-ds (workgroup:)
MAC Address: BC:24:11:FE:C7:3E (Proxmox Server Solutions GmbH)
Aggressive OS guesses: Microsoft Windows 10 1507 - 1607 (97%), Microsoft Windows 10 1511 - 1607 (96%), Microsoft Windows Vista SP2 or Windows 7 or Windows Server 2008 R2 or Windows 8.1 (96%), Microsoft Windows 7 Professional (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows Longhorn (95%), Microsoft Server 2008 R2 SP1 (95%), Microsoft Windows Server 2008 R2 SP1 or Windows 7 SP1 (95%), Microsoft Windows 7 or 8.1 R1 or Server 2008 R2 SP1 (95%), Microsoft Windows 7 or Windows Server 2008 R2 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.40 seconds
```

## Elastic Integration

I have included some resources within the `elastic` folder to help integrate your Faitour logs with Elastic for monitoring and alerting on honeypot activity. Please review the Elastic [README.md](./elastic/README.md) for details on installing those resources.

## Questions and Discussions

If you have any questions about installation, or would just like to discuss the project, please start a [discussion](../../discussions) to get the conversation going.

## Contributing

If you would like to contribute to this project, please first open an issue with your idea so we can discuss it.

## To Do

### Test and Finalize Modules

- [X] Operating System
- [X] FTP
- [ ] SSH
    - Returns from the server wrap oddly. Can this be fixed?
- [X] Telnet
- [X] HTTP
- [X] RPC
- [X] NetBIOS
- [ ] SNMP
    - Verify fingerprinting
    - Custom MIB's?
    - Logging
- [X] HTTPS
- [ ] SMB
    - Work on actual access to SMB
    - Use file system like Telnet, FTP, and SSH?
- [X] MSSQL
- [X] MySQL
- [X] RDP
- [X] PostgreSQL

### Elastic Integration

- [X] Ingest Pipeline
- [X] Security Detection Rules
- [ ] Create and submit official Elastic Integration
