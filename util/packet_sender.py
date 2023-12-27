from scapy.all import *
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import sys
sys.path.append('..')
from util.encrypt_util import EncryptUtil

class PacketGenerator(object):
    def __init__(self) -> None:
        self.int_data_offset = self.get_int_data_offset()
        self.encrypt_tool = EncryptUtil()
    
    def get_int_data_offset(self):
        eth_len = 14
        ip4_len = 20
        udp_len = 8
        total = eth_len + ip4_len + udp_len
        int_data_offset = 2 * total
        return int_data_offset

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

    def send_encrypted_packets(self, interface):
        pkts = rdpcap('/home/jia/INT_data_verification/raw_unsafe_packet_two.pcapng')
        for pkt in pkts:
            raw_packet = bytearray(bytes_hex(pkt))
            print(raw_packet)
            int_data = raw_packet[self.int_data_offset: -1]
            print(int_data)
            encrypt_int_data = self.encrypt_tool.encrypt(int_data)
            packet=Ether(src = 'f6:61:c0:6a:00:00')/IP(src='10.0.1.1',dst='10.0.2.2')/UDP(dport=53)/Raw(hex_bytes(bytes(encrypt_int_data)))
            packet.show()
            print('encrypt_int_data ---->')
            print(encrypt_int_data)
            sendp(packet, iface= interface)
            # raw_packet[self.int_data_offset: -1] = encrypt_int_data
            # # raw_packet[self.int_data_offset: -1] = b'111'
            # packet = bytes(raw_packet)
            # print(packet)
            # sendp(packet, iface=interface)


    # def encrypt(self, data):
    #     # 参数key: 秘钥，要求是bytes类型，并且长度必须是16、24或32 bytes，因为秘钥的长度可以为：128位、192位、256位
    #     # 参数mode: 加密的模式，有ECB、CBC等等，最常用的是CBC
    #     # 参数iv: 初始向量，是CBC加密模式需要的初始向量，类似于加密算法中的盐
    #     # 创建用于加密的AES对象
    #     key = b"1234123412ABCDEF"
    #     iv = b"ABCDEF1234123412"
    #     cipher1 = AES.new(key, AES.MODE_CBC, iv)
    #     # 使用对象进行加密，加密的时候，需要使用pad对数据进行填充，因为加密的数据要求必须是能被128整除
    #     # pad参数内容，第一个是待填充的数据，第二个是填充成多大的数据，需要填充成128位即16bytes
    #     ct = cipher1.encrypt(pad(data, 16))
    #     # 将加密后的结果（二进制）转换成十六进制的或者其它形式
    #     ct_hex = binascii.b2a_hex(ct)
    #     return ct_hex


    # def decrypt(self, ct_hex):
    #     key = b"1234123412ABCDEF"
    #     iv = b"ABCDEF1234123412"
    #     # 创建用于解密的AES对象
    #     cipher2 = AES.new(key, AES.MODE_CBC, iv)
    #     # 将十六进制的数据转换成二进制
    #     hex_data = binascii.a2b_hex(ct_hex)
    #     # 解密完成后，需要对数据进行取消填充，获取原来的数据
    #     pt = unpad(cipher2.decrypt(hex_data), 16)
    #     return pt

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

# send flow
    # interface = 'veth20'
    # sleep_time = 2
    # while sleep_time > 0:
    #     packet_sender.send_ipv4(interface=interface)
    #     time.sleep(0.2)
    #     sleep_time -= 1

# send encrypted pkts
    interface = 'veth28'
    packet_sender.send_encrypted_packets(interface=interface)
    
    # int_data = b'123456'
    # encry_data = packet_sender.encrypt(int_data)
    # print(encry_data)
    # decry_data = packet_sender.decrypt(encry_data)
    # print(decry_data)
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

