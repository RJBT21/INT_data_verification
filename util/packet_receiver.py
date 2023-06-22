from scapy.all import sniff

class UdpReceiver(object):
    def __init__(self, interface) -> None:
        self.interface = interface

    def udp_sniff(self):
        filter = 'net fe80::dead:beef'
        store = 1
        count = 0
        # packet = sniff(filter= filter, store = True, iface = self.interface,prn=lambda x:x.summary())
        packet = sniff(filter= filter, store = 1, iface = self.interface, prn = self.packet_show)

        print(packet)

    def packet_show(self, packet):
        layers = packet.layers()
        self.print_layers(layers)
        # print("--- parse ip ----")
        # self.parse_ip(packet)
        # print("--- parse ether ---")
        # self.parse_ether(packet)
        print("--- parse ipv6 ---")
        self.parse_ipv6(packet)

        print("--- parse AH ---")
        self.parse_AH(packet)
        # print("--- parse udp ---")
        # self.parse_udp(packet)

        # packet.show(dump = False)

    def parse_ip(self,packet):
        ip = packet['IP']
        print("--- src ---")
        src = ip.src
        print(src)
        print('--- dst ---')
        dst = ip.dst
        print(dst)
        ip.show()
    
    def parse_ether(self, packet):
        ether = packet['Ethernet']
        print(ether)
        ether.show()
    
    def parse_udp(self, packet):
        udp = packet['UDP']
        print(udp)
        udp.show()

    def parse_ipv6(self, packet):
        ipv6 = packet['IPv6']
        print(ipv6)
        print("--- src ---")
        src = ipv6.src
        print(src)
        print("--- dst ---")
        dst = ipv6.dst
        print(dst)

        ipv6.show()

    def parse_AH(self, packet):
        ah = packet['AH']
        print(ah)
        print("--- spi ---")
        # spi --> Identifier of PAH，32bit 
        spi = ah.spi
        print(spi)
        print("--- seq ---")
        # seq --> OTP（One-time password）value，32bit
        seq = ah.seq
        print(seq)

        


    def print_layers(self, layers):
        for i in range(len(layers)):
            print("--- layer %s---", layers[i].__name__)
            print(layers[i])


if __name__ == '__main__':
    udpReceiver = UdpReceiver(interface= 'ens33')
    udpReceiver.udp_sniff()