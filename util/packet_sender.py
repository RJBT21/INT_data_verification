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

    def send_ipv4(self, interface):
        packet=Ether(src = 'f6:61:c0:6a:00:00')/IP(src='10.0.1.1',dst='10.0.2.2')/UDP(dport=53)
        packet.show()
        sendp(packet, iface= interface)



if __name__ == '__main__':
    packet_sender = PacketGenerator()
    # packet_sender.send(interface= 'ens33', dst_ip= '2001:db8:cafe:f000::')
    # switch_id = 1
    # totp_code = '0511391894'
    # packet_sender.send_extension_AH(interface= 'veth132', switch_id= switch_id, totp_code= totp_code)
    # for i in range(5):
    #     packet_sender.send_ipv6(interface= 'veth3')
    #     time.sleep(2)
    # totp_code = '0663671716'
    # totp_code_encod_utf8 = totp_code.encode('utf8')
    # print(totp_code_encod_utf8)
    # totp_code_encoded_int = int(totp_code_encod_utf8)
    # print(totp_code_encoded_int)
    # totp_code_bytes = bytes(totp_code_encoded_int)
    # print(totp_code_bytes)

    interface = 'veth20'
    sleep_time = 200
    while sleep_time > 0:
        packet_sender.send_ipv4(interface=interface)
        time.sleep(0.2)
        sleep_time -= 1
    # packet_sender.send_ipv4(interface=interface)
    
    # start_time = time.time()
    # time.sleep(1)
    # end_time = time.time()
    # fractional_seconds = time.perf_counter() % 1
    # start_time_microseconds = int(start_time * 1e6) + int(fractional_seconds * 1e6)
    # end_time_microseconds = int(end_time * 1e6) + int(fractional_seconds * 1e6)
    # execution_time = end_time_microseconds - start_time_microseconds
    # print(execution_time * 1e-3)

# 2653725000000
# 2656238750000

