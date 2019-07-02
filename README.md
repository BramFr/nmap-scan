# nmap-scan

This is a easy scan based on nmap with dns lookup. It will also find hosts where ICMP are blocked. 
When ICMP its blocked it will scan for common ports like 22,23,80,139,443,445,3389. If one of these ports are open result will be up.

It can also scan for duplicate IP`s based on MAC changed.

## Info
```console
# sudo ./nmap-scan.py -h
Easy Nmap Scan ( https://github.com/BramFr/nmap-scan )
 Usage: sudo ./nmap-scan.py {target specification} [Scan Type(s)]

 Scan Type(s):
    --arp scan for duplicate IP (infinity loop)

 Example: 
     sudo ./nmap-scan.py                    (this wil scan default network)
     sudo ./nmap-scan.py --arp              (this wil scan default network with arp scanning)
     sudo ./nmap-scan.py 172.25.0.0/24 --arp (only works within same network)
     sudo ./nmap-scan.py 172.25.0.55

```

## Dependency
```console
# sudo pip3 install -r requirements.txt
# sudo apt-get install nmap
```