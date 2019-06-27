# nmap-scan

This is a easy scan based on nmap with dns lookup. It can also find duplicate IP`s based on MAC changed.

## Info
```console
# sudo ./nmap-scan.py -h
Easy Nmap Scan ( https://github.com/BramFr/nmap-scan )
 Usage: sudo ./nmap-scan.py [Scan Type(s)] {target specification}

 Scan Type(s):
    --arp for fineding duplicate IP (infinity loop)

 Example: 
     sudo ./nmap-scan.py 172.25.0.0/24 --arp
     sudo ./nmap-scan.py 172.25.0.55

```

## Dependency
```console
# sudo pip3 install -r requirements.txt
# sudo apt-get install nmap
```