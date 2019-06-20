#!/usr/bin/env python3
import sys
import nmap
import socket

ip_range = sys.argv[1].split('/')


def _valid_ip(ip_range):
    try:
        socket.inet_aton(ip_range[0])
        return True
    except:
        return False

def _nmapscan(ip_range):
    if len(ip_range) == 2:
        scan_ip = ip_range[0] + "/" + ip_range[1]
    else:
        scan_ip = ip_range[0]

    nm = nmap.PortScanner()
    nm.scan(
        hosts=scan_ip,
        arguments='-n -sP -PE -PA23,22,443,80,3389,445,139')

    hosts_list = [(x, nm[x]['status']['state'], nm[x]['hostnames'][0]['name'])
            for x in nm.all_hosts()]
    return hosts_list


def _main():
    if not _valid_ip(ip_range):
        print("Wrong IP. please give something like: 172.25.0.25 or 172.25.0.0/24")
        # exit()

    for host, status, hostname in _nmapscan(ip_range):
        if not hostname:
            try:
                dns_hostname = socket.gethostbyaddr(host)
            except:
                dns_hostname = ["Unknown_host"]

    #    print(f'{host}:{status}:{dns_hostname[0]}')
        print("{}:{}:{}".format(host, status, dns_hostname[0]))


if __name__ == '__main__':
    _main()
