from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
import os
import atexit

def exit_handler():
    nfqueue.unbind()
    os.system("sudo iptables -F")


atexit.register(exit_handler)
#msg = "\xe6\xf9\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00\x06status\x07discord\x03com\x08Ctsystem\x00\x00\x01\x00\x01"

#msg2 = "\xa0\x00\xdb}l@\x006\x11\xfc\xa4\xbczK\xd6\xc0\xa8\x00h\xc3R\x99\xdc\x00\xc7\x8d\x06\x90oL\xc4\xf8\x87\x9c\xae\x00\x0e\x0b\xbd\xbe\xde\x00\x01\x10\x9c\x9"
#new_str = unicodedata.normalize("NFKD", msg2)
#print(new_str)
def print_and_accept(pkt):
    packet = (IP(pkt.get_payload()))
    for p in packet:
        a = p.show(dump=True)
        print(a)
    pkt.accept()
os.system("sudo iptables -I INPUT -j NFQUEUE --queue-num 1")

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')
