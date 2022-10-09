import os
import socket
import time
from datetime import datetime
import ipaddress

def isOpen(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
        s.shutdown(2)
        return True
    except:
        return False

def search_list(keyword, list):
    search = []

    for i in list:
        if keyword in i:
            search.append(i)
    
    return search

class Netscan:
    def __init__(self):
        self.prev_net_scan = {}
        self.prev_port_scan = {}

    def network_scan(self, ip, ping=True):
        network = ipaddress.ip_network(ip)
        num_hosts = len(list(network.hosts()))
        hosts = network.hosts()

        open = []
        hosts_up = 0
        start_time = time.perf_counter()

        print(f'Netscan 1.0 running at {datetime.date(datetime.now())} {datetime.time(datetime.now())}\n')

        for host in hosts:
            try:
                hostname = socket.gethostbyaddr(str(host))
                hostname = f"{hostname[0]} ({hostname[2][0]})"
            except socket.herror:
                hostname = host
            
            if ping:
                stream = os.popen(f"ping -c 1 -W 0.1 {host}")
                s_r_l = stream.readlines()

                if len(s_r_l) > 0 and "1 received" in s_r_l[-2]:
                    t = s_r_l[1].split('time=')[1].split('\n')[0]
                    
                    print(f"Netscan scan report for {hostname}")
                    print(f"Host is up ({t} latency)\n")

                    open.append({
                        'host': host,
                        'name': hostname,
                        'time': t
                    })

                    hosts_up += 1
            else:
                print(f"Netscan scan report for {hostname}")
        
        end_time = time.perf_counter()
        delta_time = str(end_time - start_time)[0:4]

        print(f"Netscan done: {num_hosts} IP addresses ({hosts_up} hosts up) scanned in {delta_time} seconds")
    
    def port_scan(self, ip, ports='1000', single_port=False, verbose=False):
        network = ipaddress.ip_network(ip)
        num_hosts = len(list(network.hosts()))
        hosts = network.hosts()

        s = ports.split('-')

        start = (int(s[0]) if '-' in ports else 1) if not single_port else int(ports)
        end = 65535 if ports == "all" else (int(s[1]) if '-' in ports else int(ports)) if not single_port else int(ports)

        open = []

        print(f"Starting Netscan 1.0 at {datetime.date(datetime.now())} {datetime.time(datetime.now())}\n")

        start_time = time.perf_counter()

        for host in hosts:
            try:
                hostname = socket.gethostbyaddr(str(host))
                hostname = f"{hostname[0]} ({hostname[2][0]})"
            except socket.herror:
                hostname = host
            
            print(f"Port scan for host {hostname}\n")
            print("PORT      STATUS SERVICE")

            for port in range(start, end+1):
                o = isOpen(str(host), port)
                s = 5 - len(str(port))
                s = "".join([" " for i in range(s)])
                type = 'tcp'

                try:
                    service = socket.getservbyport(port, 'tcp')
                    type = 'tcp'
                except:
                    try:
                        service = socket.getservbyport(port, 'udp')
                        type = 'udp'
                    except:
                        type = "unknown"
                
                if o:
                    open.append({
                        "port":port,
                        "type":type,
                        "service":service
                    })
                    
                    print(f"{port}/{type}{s} open   {service}")
                elif verbose:
                    print(f"{port}/{type}{s} closed {service}")
        

        end_time = time.perf_counter()
        delta_time = str(end_time - start_time)[0:4]

        print(f"\n{len(open)} open port(s), {(end - start + 1) - len(open)} closed")
        print(f"\nNetscan done: {num_hosts} IP addresses and {end - start + 1} port(s) scanned in {delta_time} seconds")
