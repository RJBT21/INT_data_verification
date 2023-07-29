from scapy.all import *

class PacketGenerator(object):
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

    def send_extension_AH(self, interface, switch_id, totp_code):
        base = IPv6()
        base.src = 'fe80::dead:beef'
        base.dst = 'fe80::1234'

        extension = AH()
        extension.payloadlen = 2     # 8bit
        extension.nh = 17            # 8bit 
        extension.spi = switch_id     # 32bit
        extension.seq = int(totp_code.encode('utf-8'))  # 32bit
        extension.icv = b'11111111'        # 128bit
        extension.padding = None
        packet = Ether(src = '00:00:00:00:00:01', dst = '00:00:00:00:00:02')/base/extension/UDP(dport = 4953)
        packet.show()
        sendp(packet, iface= interface)
    
    def send_ipv6(self, interface):
        base = IPv6()
        base.src = 'fe80::dead:beef'
        base.dst = 'fe80::1234'

        packet = Ether(src = '00:00:00:00:00:01', dst = '00:00:00:00:00:02')/base/UDP(dport = 4953)
        packet.show()
        sendp(packet, iface= interface)



if __name__ == '__main__':
    packet_sender = PacketGenerator()
    # packet_sender.send(interface= 'ens33', dst_ip= '2001:db8:cafe:f000::')
    switch_id = 1
    totp_code = '0703361050'
    # packet_sender.send_extension_AH(interface= 'ens33', switch_id= switch_id, totp_code= totp_code)
    for i in range(10):
        packet_sender.send_ipv6(interface= 'veth3')
        time.sleep(2)
    # totp_code = '0663671716'
    # totp_code_encod_utf8 = totp_code.encode('utf8')
    # print(totp_code_encod_utf8)
    # totp_code_encoded_int = int(totp_code_encod_utf8)
    # print(totp_code_encoded_int)
    # totp_code_bytes = bytes(totp_code_encoded_int)
    # print(totp_code_bytes)
