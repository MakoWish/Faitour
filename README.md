# Faitour 2.0

**fai*tour ('fei ter)**  
n. Archaic  
[1300-1350] Middle English - A charlatan or imposter

![Faitour 2](logo_wide.png){width="100%"}

## About

Faitour 2 is a complete rewrite of [MakoWish/Faitour](https://github.com/MakoWish/Faitour). which was originally forked from [eightus/Cyder](https://github.com/eightus/Cyder), so I must first give credit to that project for the inspiration. The issue with the original Faitour was that packets to any real services would be intercepted and not properly forwarded, so the services were rendered useless. This defeated the purpose of working alongside OpenCanary. For this reason, I decide to start from scratch and try to create my own honeypot with some fully-functional services. 

The idea behind this project was to not only spoof services to NMAP scans, but also log all access attempts in a format that follows the Elastic Common Schema. This will make parsing the logs much easier for ingestion into Elasticsearch. Once I feel this project has matured a bit more, I will work on an Elastic Agent integration to take all the work out of ingesting these logs, as well as creating Elastic Security alerts based on observed activity. 

## Supported Operating Systems

This project was built on, and has been tested on, Ubuntu 24.04 LTS. Other operating systems **_may_** work , but I have not tested any others.

## Installation

### Download

I typically install optional software to `/opt`, so I would navigate there first, then clone the project.

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

Optionally, configure logging to fit your needs. By default, both file and stdout logging are enabled, but you may turn either or both off. If running as a `systemd` service, the stdout logging will be written to the system journal.

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

#### Operating System and Services

Beyond the basic network and logging configuration, you will also see details for the operating system and service fingerprints in your config file. By default, the operating system is set to Microsoft Windows Server 2008 R2, and some basic Windows services are enabled. Enable or disable services as you would like to suit your needs

If you would like to change fingerprints, please reference the NMAP fingerprints databases:

Operating System Fingerprints can be found at: https://svn.nmap.org/nmap/nmap-os-db

Service Fingerprints can be found at: https://svn.nmap.org/nmap/nmap-service-probes

### Starting

To start Faitour as systemd service, enable and start the service. You may optionally follow the journal logs to ensure the service started without issue:

```bash
sudo systemctl enable faitour.service
sudo systemctl start faitour.service
sudo journalctl -fu faitour.service
```

To start Faitour manually, simply execute with Python as root.

```bash
sudo ./faitour.py
```

### Testing

Once Faitour has been started, be sure to run an NMAP scan from another machine to ensure that everything is working as expected. 

`nmap -sS -sV -O <ip address>`

## Contributing

If you would like to contribute to this project, please first open an issue with your idea, then create a pull request that is linked to the issue you created. 
