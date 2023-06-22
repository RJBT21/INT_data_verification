from scapy.all import *

class Packet_Generator(object):
    def __init__(self) -> None:
        pass

    def send(self, interface, dst_ip):
        packet = Ether(src = '00:00:00:00:00:01', dst = '00:00:00:00:00:02')/IPv6(dst = dst_ip)/UDP(dport = 53)
        print(packet)
        sendp(packet,iface=interface)

    def send_extension(self, interface):
        base = IPv6()
        base.src = 'fe80::dead:beef'
        base.dst = 'fe80::1234'
        extension = IPv6ExtHdrHopByHop()
        jumbo = Jumbo()
        jumbo.jumboplen = 2**30
        extension.options = jumbo
        packet = Ether(src = '00:00:00:00:00:01', dst = '00:00:00:00:00:02')/base/extension/UDP(dport = 4953)
        packet.show()
        sendp(packet, iface= interface)

    def send_extension_AH(self, interface):
        base = IPv6()
        base.src = 'fe80::dead:beef'
        base.dst = 'fe80::1234'

        extension = AH()
        extension.payloadlen = 2     # 8bit
        extension.nh = 17            # 8bit 
        extension.spi = 123456       # 32bit
        extension.seq = 2341833143   # 32bit
        extension.icv = 1111        # 128bit
        extension.padding = 0
        packet = Ether(src = '00:00:00:00:00:01', dst = '00:00:00:00:00:02')/base/extension/UDP(dport = 4953)
        packet.show()
        sendp(packet, iface= interface)



if __name__ == '__main__':
    packet_sender = Packet_Generator()
    # packet_sender.send(interface= 'ens33', dst_ip= '2001:db8:cafe:f000::')
    packet_sender.send_extension_AH(interface= 'ens33')
