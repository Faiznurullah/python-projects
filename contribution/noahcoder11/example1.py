from netscan import Netscan

n = Netscan()

# Search for connected hosts on the local network 192.168.0.0/24
n.network_scan("192.168.0.0/24")