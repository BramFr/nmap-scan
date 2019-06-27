# nmap-scan

This is a easy scan based on nmap with dns lookup. It will also find hosts where ICMP are blocked. 
When ICMP its blocked it will scan for common ports like 21,22,80,443,3389. If one of these ports are open result will be up.

It can also scan for duplicate IP`s based on MAC changed.

## Info
```console
# sudo ./nmap-scan.py -h
Easy Nmap Scan ( https://github.com/BramFr/nmap-scan )
 Usage: sudo ./nmap-scan.py [Scan Type(s)] {target specification}

 Scan Type(s):
    --arp scan for duplicate IP (infinity loop)

 Example: 
     sudo ./nmap-scan.py 172.25.0.0/24 --arp
     sudo ./nmap-scan.py 172.25.0.55

```

## Dependency
```console
# sudo pip3 install -r requirements.txt
# sudo apt-get install nmap
```