from scapy.all import *

class Packet_Generator(object):
    def __init__(self) -> None:
        pass

    def send(self, interface, dst_ip):
        packet = Ether(src = '00:00:00:00:00:01', dst = '00:00:00:00:00:02')/IP(dst = dst_ip)/UDP(dport = 53)
        print(packet)
        sendp(packet,iface=interface)


if __name__ == '__main__':
    packet_sender = Packet_Generator()
    packet_sender.send(interface= 'ens33', dst_ip= '198.2.6.9')
