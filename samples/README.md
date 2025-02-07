# Service Fingerprinting Samples

### About these Samples

Within this directory, you will find some sample fingerprints that will help you to fool NMAP scans into thinking the emulated services are the versions you choose. Some services only require a fingerprint, but some also include logon banners or server banners. Be sure to adjust these to your preferences when placing them into your `./config.yml`.

### Adding Fingerprints

All fingerprints within this directory have been tested and confirmed to work, but you are welcome to add more. The key to a working fingerprint is generating a string that matches an NMAP fingerprinting attempt. You can find NMAP's service fingerprinting strings [HERE](https://svn.nmap.org/nmap/nmap-service-probes). The regex pattern that NMAP uses will always be within the pipes `|`. One example could be SMB for Microsoft Windows Server 2008 R2. The complete line looks like this:

```
match microsoft-ds m|^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04A\0\0\0\0\x01\0\0\0\0\0\xfc\xf3\x01\0.{21}((?:..)*)\0\0((?:..)*)\0\0|s p/Microsoft Windows Server 2008 R2 - 2012 microsoft-ds/ i/workgroup: $P(1)/ o/Windows/ h/$P(2)/ cpe:/o:microsoft:windows/
```

Between the pipes, you will find the regex pattern:

```
^\0\0\0.\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0.2\0\x01\0\x04A\0\0\0\0\x01\0\0\0\0\0\xfc\xf3\x01\0.{21}((?:..)*)\0\0((?:..)*)\0\0
```

Breaking this down, we can generate a string that matches this pattern:

```
\0\0\0a\xffSMBr\0\0\0\0\x88\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\x11\x07\0a2\0\x01\0\x04A\0\0\0\0\x01\0\0\0\0\0\xfd\xe3\x01\0ABCDEFGHIJKLMNOPQRSTU\0\0\0\0
```

To test the match, you can use a text editor like Kate or Notepad++, but be sure to first escape the backslashes in the regex pattern.

### Contributing

If you add some strings of your own, and you can confirm they work, please let me know, and I will have them added here. 
