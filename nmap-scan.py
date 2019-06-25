#!/usr/bin/env python3
import sys
import os
import nmap
import socket
from tabulate import tabulate


ip_range = sys.argv[1].split('/')
# ip_range = ['172.16.0.0','24']


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
    nm.scan(hosts=scan_ip, arguments='-Pn -p23,22,443,80,3389,445,139')

    return _formatResult(nm)

def _formatResult(nm):
    hosts_list = []
    for x in nm.all_hosts():
        host_list = []

        # Added IP to list.
        host_list.append(x)

        '''
        Check if any port is open. 
        If some port is open state will be up
        '''
        for port_status in nm[x]['tcp']:
            if nm[x]['tcp'][port_status]['state'] == 'open':
                host_list.append('up')
                break
        else:
            host_list.append('down')

        '''Trying to get FQDN from DNS'''
        try:
            host_list.append(socket.gethostbyaddr(x)[0])
        except:
            host_list.append('Unknown_host')


        '''
        Lookup MAC address this will only work in the same network.
        '''
        try:
            host_list.append(nm[x]['addresses']['mac'])
        except:
            host_list.append('null')
        hosts_list.append(host_list)

    return hosts_list


def _main():
    # if os.getuid() != 0:
    #     print("This program requires root privileges.  Run as root using 'sudo'.")
    #     sys.exit()

    if not _valid_ip(ip_range):
        print("Wrong IP. please give something like: 172.25.0.25 or 172.25.0.0/24")
        # exit()

    scanResults = _nmapscan(ip_range)
    headers = ["Host_IP", "Status", "Hostname", "mac"]
    print(tabulate(scanResults, headers, tablefmt="presto"))


if __name__ == '__main__':
    _main()
