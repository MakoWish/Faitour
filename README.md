# Faitour

**fai*tour ('fei ter)**  
n. Archaic  
[1300-1350] Middle English - A charlatan or imposter  

# About

Faitour was cloned from [eightus/Cyder](https://github.com/eightus/Cyder), so I must first give credit to that project. Although that project is no longer maintained, you can still reference it for the original version.

Faitour has been stripped down to simply the OS emulation capabilities, and I have tried to simplify installation on Ubuntu 22.04. This was intended to be a quick and simple compliment to OpenCanary to more closely emulate different operating systems for NMAP fingerprinting.

Cyder was originally a Honeypot that was designed to imitate any Operating System (OS) that is available in the NMAP database. What remains in Faitour is the ability to detect NMAP probes and reply with spoofed OS and service fingerprints.

## Prerequisites

This project has been tested on Ubuntu 22.04 LTS. However, other operating systems **_may_** work if they have the following libraries:

- iptables
- libnetfilter_queue
- Python 3.6+

_For Ubuntu 16, you must upgrade Python to 3.6._

## Installation

### Download

I typically install optional software to `/opt`, so I would navigate there first:

`cd /opt`

Clone the repo to your machine:

`sudo git clone https://github.com/MakoWish/Faitour.git`

### Setup

#### Ubuntu 22.04 LTS

A script is provided at `./setup.sh` to install all the required libraries, python modules, and create a SystemD service.

`sudo ./setup.sh`

#### Other Linux Flavors

I have unfortunately been unable to get this working on Ubuntu 24.04 due to Python packages that are unavailable. If you are able to get Faitour working on Ubuntu 24.04, please let me know so I can make some changes here.

No other operating systems have been tested.

### Configuration

After installing, you should change the configurations before starting the service.

The configuration file is located at:

`./configuration/host_config.ini`

Example configurations may be found in:

`./configuration/sample_configs/<description>/`

### Default Configuration:

The follwoing default configuration will be installed with Faitor in `./configuration/host_config.ini`. This will emulate a Windows Server 2012 R2 with the basic RPC, SMB, and RDP services that you would find on a typical Server 2012 R2 installation. The RPC fingerprints were chosen to match a real-world scan of a Server 2012 R2 box. 

_IMPORTANT!_ As with all configurations, including the sample configurations provided, you must update the `interface` and `ip` values to match your device's configuration, or spoofing will not work. 

```
[CONFIGURATION]
# Set network details to match your host
interface = eth0
ip = 10.10.10.10
mac_address = false
mac = 00:11:22:33:44:55

[LOGGING]
# DEBUG, INFO, WARNING, ERROR
logLevel = INFO
logDir = /var/log/faitour/
logSize = 10000000
logCount = 10
logPackets = True

[HOST]
# Windows Server 2012 R2 Emulation
fingerprint = SEQ(SP=F7-101%GCD=1-6%ISR=FD-107%TI=I%CI=I%II=I%SS=O%TS=7)
	OPS(O1=M5B4NW8ST11%O2=M5B4NW8ST11%O3=M5B4NW8NNT11%O4=M5B4NW8ST11%O5=M5B4NW8ST11%O6=M5B4ST11)
	WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
	ECN(R=Y%DF=Y%T=7B-85%TG=80%W=2000%O=M5B4NW8NNS%CC=Y%Q=)
	T1(R=Y%DF=Y%T=7B-85%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
	T2(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
	T3(R=N)
	T4(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
	T5(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
	T6(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
	T7(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
	U1(DF=N%T=7B-85%TG=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
	IE(DFI=N%T=7B-85%TG=80%CD=Z)

# Microsoft SMB Emulation
139 = \x83\0\0\x01\x8f$
445 = \0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04A\0\0\0\0\x01\0\0\0\0\0\xfc\xe3\x01\0

# Windows RPC Emulation
135 = \x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$

# Microsoft RDP
3389 = \x03\0\0*%\xe0\0\0\0\0\0

```

Remember to change the interface name and IP address to match your device settings.

## Starting the Emulator

To run the OS emulator, simply start the systemd service by running:

`sudo systemctl start faitour.service`

## Fingerprints & Services

Operating System Fingerprints can be found at: https://svn.nmap.org/nmap/nmap-os-db

Service Fingerprints can be found at: https://svn.nmap.org/nmap/nmap-service-probes

Be sure to run an NMAP scan from another machine to ensure that everything is working as expected. 

`nmap -sS -sV -O <ip address>`

## Key Files

`./setup.sh`
  - Setup script for Ubuntu 22.04 LTS

`./configuration/host_config.ini`
  - Configuration for OS emulation

## Logging

Logs are stored in `/var/log/faitour` by default, but the path may be modified in `host_config.ini`. Logging is written to both stdout (systemd journal) and text file. Optionally enable packet logging in `host_config.ini`.

**faitour**

- Log core application events.

**packet.json**

- Contains the packet bytes the host received. **NOTE:** it does not contain packets that are sent out.
- Example of Packet Log:
- `{"timestamp": 1577678695.520519, "dst_ip": "x.x.x.x", "host_os": "HOST", "src_ip": "x.x.x.x", "services": 22, "packet": "d2h5IGRpZCB5b3UgZXZlbiB0cnkgdG8gZGVjb2RlIHRoaXM/IEkgd291bGRuJ3QgcHV0IGEgcmVhbCBwYWNrZXQgaGVyZQ==\n"}`
- The packet is base64 encoded.To decode it, use:
- `base64.decodebytes(packet.encode('ascii'))`
- This will return you the actual bytes.
- `services` is the port number.

## Limitations and Known Issues

### Limitations:

- NMAP may yield an inaccurate result during an aggressive scan, but it should not affect the average NMAP fingerprinting.
- UDP Packets are dropped due to the inability to spoof the OS.

### Known Issues:

None yet. Please report any issues you encounter.

## Contributing

If you would like to contribute to this project, including code changes or configuration examples, please first open an issue with your idea, then create a pull request that is linked to the issue you created. 

## TODO

* [x] Operating System Spoofing
* [X] Code Clean Up of Cyder's Honeypot Functionality
* [X] Enahnce logging
* [ ] Create additional sample configurations for OS/Service configurations

## Credits

* [@eightus](https://github.com/eightus) for the original Cyder project
* [@1Stronk](https://github.com/1Stronk) for some tips on getting this to work on Ubuntu 22.04
