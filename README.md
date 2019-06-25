# nmap-scan

This is a easy scan based on nmap with dns lookup. Dependency python-nmap and nmap. 

## example
```console
# ./nmap-scan.py 172.31.254.0/24
 Host_IP        | Status   | Hostname     | mac
----------------+----------+--------------+-------
 172.16.161.0   | down     | Unknown_host | null
 172.16.161.1   | up       | _gateway     | null
 172.16.161.10  | down     | bizarro      | null
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