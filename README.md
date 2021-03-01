# DNS Spoofing Application

## Running the Application

### On the Attacker Machine
1. Configure the file `config1.txt` by entering the IP addresses and MAC address of the following fields respectively:
  - victimIP
  - routerIP
  - routerMAC
  - victimMAC
  
2. Start the ARP Spoofing application by running `python3 arp-spoof.py`
3. Start the DNS Spoofing application by running `python3 dns-spoof.py`. To see the optional parameters, run `python3 dns-spoof.py -h`. 
```
usage: dns-spoof.py [-h] [-r DNS_RESPONDER_IP] [-t TARGET_IP] [-i NETWORK_INTERFACE] [-s SPOOF_IP]

optional arguments:
  -h, --help            show this help message and exit
  -r DNS_RESPONDER_IP, --responder DNS_RESPONDER_IP    
                        DNS Responder IP
  -t TARGET_IP, --target TARGET_IP
                        DNS Spoof Victim IP
  -i NETWORK_INTERFACE, --interface NETWORK_INTERFACE  
                        Network Interface
  -s SPOOF_IP, --spoof-ip SPOOF_IP
                        Spoof IP address
```
e.g. `python3 dns-spoof.py -r 192.168.1.103 -t 192.168.1.104 -i enp0s8 -s 1.1.1.1`

### On the Victim Machine
Once the spoofing scripts have been started, victim machine can start testing the application by performing actions such as `nslookup`, `ping`, `dig`, or `traceroute`.
e.g. `ping github.com`, `nslookup github.com`, `dig github.com`, `traceroute github.com`
