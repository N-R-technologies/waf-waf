from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.all import *
import os
import atexit

# msg = "\xe6\xf9\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00\x06status\x07discord\x03com\x08Ctsystem\x00\x00\x01\x00\x01"
# msg2 = "\xa0\x00\xdb}l@\x006\x11\xfc\xa4\xbczK\xd6\xc0\xa8\x00h\xc3R\x99\xdc\x00\xc7\x8d\x06\x90oL\xc4\xf8\x87\x9c\xae\x00\x0e\x0b\xbd\xbe\xde\x00\x01\x10\x9c\x9"
# new_str = unicodedata.normalize("NFKD", msg2)
# print(new_str)

def exit_handler():
    """
    This function will unbind the netfilter queue object and will remove the iptables
    rule that was assigned when the program is being terminated
    """
    nfqueue.unbind()
    os.system("sudo iptables -F")

def print_and_accept(pkt):
    """
    This function will be called every time a packet is received in the network traffic.
    It will check if this packet might be an attack with the help of other functions.
    If it is an attack, the packet will be dropped and won't reach the user's computer.
    Otherwise, the packet will be accepted and it will continue to its destination.
    :param pkt: the received packet that the program will check if it's might be an attack or not.
    """
    packet = IP(pkt.get_payload())
    if Raw in packet:
        load = packet[Raw].load
        hexdump(load)
        print()
    pkt.accept()

def main():
    atexit.register(exit_handler)
    os.system("sudo iptables -I INPUT -j NFQUEUE --queue-num 1")

    nfqueue.bind(1, print_and_accept)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

if __name__ == "__main__":
    nfqueue = NetfilterQueue()
    main()