from scapy.all import sniff

class UdpReceiver(object):
    def __init__(self, interface) -> None:
        self.interface = interface

    def udp_sniff(self):
        filter = '198.2.6.9'
        store = 1
        count = 0
        # packet = sniff(filter= filter, store = True, iface = self.interface,prn=lambda x:x.summary())
        packet = sniff(filter= filter, store = 1, iface = self.interface, prn = self.packet_show)

        print(packet)

    def packet_show(self, packet):
        packet.show()


if __name__ == '__main__':
    udpReceiver = UdpReceiver(interface= 'ens33')
    udpReceiver.udp_sniff()