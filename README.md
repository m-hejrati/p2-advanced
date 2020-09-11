# Packet Sniffer
Packet sniffer with C language and pcap

## Installation

we use libpcaq library in this project, for installing it you can write this command:
```bash
sudo apt-get install libpcap-dev
```
for compiling C program we should add -lpcap:
```bash
gcc sniffer.c -o sniffer.out -lpcap
````
and it needs to run with sudo:
```bash
sudo ./sniffer.out
````