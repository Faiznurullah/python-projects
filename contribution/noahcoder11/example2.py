from netscan import Netscan

n = Netscan()

# Search well-known ports
n.port_scan("192.168.0.1", "1023")