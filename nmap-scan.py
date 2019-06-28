#!/usr/bin/env python3
import sys
import os
import nmap
import socket
import pandas as pd

start_aggr = sys.argv
# start_aggr = sys.argv[1].split('/')
# ip_range = ['172.31.254.0','24']

def _valid_ip(start_aggr):
    try:
        ip_range = start_aggr[1].split('/')
        socket.inet_aton(ip_range[0])
        if len(ip_range) == 2:
            scan_ip = ip_range[0] + "/" + ip_range[1]
        else:
            scan_ip = ip_range[0]
    except:
        print("Wrong IP. please give something like: 172.25.0.25 or 172.25.0.0/24\n\
            use -h for more help."                                                                                                                                        )
        exit()
    return scan_ip


def _nmapscan_default(scan_ip):
    nm_ping = nmap.PortScanner()
    nm_ping.scan(hosts=scan_ip, arguments='-sP', sudo=True)
    nm = nmap.PortScanner()
    nm.scan(
        hosts=scan_ip,
        arguments='-Pn -p23,22,443,80,3389,445,139',
        sudo=True)

    host_list = {}
    for host in nm.all_hosts():
        # Added IP to list.
        host_list[host] = {}
        '''
        Check if any port is open. 
        If some port is open state will be up
        '''
        if host in nm_ping.all_hosts():
            if nm_ping[host]['status']['state'] == 'up':
                host_list[host]['status'] = 'up'
        else:
            for port_status in nm[host]['tcp']:
                if nm[host]['tcp'][port_status]['state'] == 'open':
                    host_list[host]['status'] = 'up'
                    break
            else:
                host_list[host]['status'] = 'down'
        host_list[host]['hostname'] = _resolvHostname(host)
        '''
        Lookup MAC address this will only work in the same network.
        '''
        try:
            host_list[host]['mac'] = nm[host]['addresses']['mac']
        except:
            host_list[host]['mac'] = 'null'
    print_result(host_list)
    # return hosts_list
    # return _formatResult(nm, nm_ping)


def _nmapscan_arp(scan_ip):
    arp_results = {}
    nm = nmap.PortScanner()
    while True:
        nm.scan(hosts=scan_ip, arguments='-sP', sudo=True)

        for host in list(arp_results):
            if host not in nm.all_hosts():
                arp_results.pop(host)

        for host in nm.all_hosts():
            if 'mac' in nm[host]['addresses']:
                if not arp_results.get(host):
                    arp_results[host] = {}

                    arp_results[host]['mac'] = nm[host]['addresses']['mac']
                else:
                    if arp_results[host]['mac'] != nm[host]['addresses'][
                            'mac']:
                        arp_results[host]['ip_conflict'] = 'True'
                        arp_results[host]['diff_mac'] = nm[host]['addresses'][
                            'mac']
                        print("HELP!!!!!")

                arp_results[host]['hostname'] = _resolvHostname(host)
            else:
                arp_results[host] = {}
                arp_results[host]['mac'] = 'Null'
        # print(arp_results)
        # headers = ["Host_IP", "Status", "Hostname", "mac"]
        os.system('clear')
        print_result(arp_results)


def _resolvHostname(ip_addr):
    try:
        hostname = socket.gethostbyaddr(ip_addr)[0]
    except:
        hostname = 'Unknown_host'
    return hostname


def print_result(raw_result):
    pd.set_option('display.max_rows', 1000)
    df = pd.DataFrame(raw_result).T
    df.fillna(0, inplace=True)
    print(df)


def _main():
    if os.getuid() != 0:
        print("This program requires root privileges.  Run as root using 'sudo'.")
        # sys.exit()


    if '--arp' in start_aggr:
        _nmapscan_arp(_valid_ip(start_aggr))
        exit()
    elif '-h' in start_aggr:
        print("Easy Nmap Scan ( https://github.com/BramFr/nmap-scan )\n \
Usage: sudo ./nmap-scan.py {target specification} [Scan Type(s)]\n\n \
Scan Type(s):\n\
    --arp scan for duplicate IP (infinity loop)\n\n \
Example: \n \
    sudo ./nmap-scan.py 172.25.0.0/24 --arp\n \
    sudo ./nmap-scan.py 172.25.0.55")
    else:
        _nmapscan_default(_valid_ip(start_aggr))
        exit()


if __name__ == '__main__':
    _main()
