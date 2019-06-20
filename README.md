# nmap-scan

This is a easy scan based on nmap with dns lookup. Dependency python-nmap and nmap. 

## example
```console
# ./nmap-scan.py 172.31.254.0/24
172.31.254.11:up:clienta.contoso.local
172.31.254.15:up:clientb.contoso.local
172.31.254.150:up:Unknown_host
```

```console
# ./nmap-scan.py 172.31.254.11
172.31.254.11:up:clienta.contoso.local
```

## Dependency
```console
# pip3 install -r requirements.txt
# apt-get install nmap
```