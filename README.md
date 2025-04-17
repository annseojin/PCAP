## PCAP Programming

### 1. Ethernet
### 2. IP
### 3. TCP

## Configuration
```
sudo apt update
sudo apt upgrade
sudo apt install -y git net-tools python3 wireshark python3-pip gedit scapy
sudo apt install libpcap-dev
```

 ## Usage
 ```
gcc packet_scan.c -o packet_scan -lpcap
sudo ./packet_scan
```
