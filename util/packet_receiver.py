import binascii
import socket
from scapy.all import sniff,bytes_hex,hex_bytes
from multiprocessing import Process,Queue
import datetime,time

QUEUE_CAPACITY = 100

class UdpReceiver(object):
    def __init__(self, interface) -> None:
        self.interface = interface
        self.message_queue = Queue(QUEUE_CAPACITY)
        self.sniff_process = []
        self.totp_offset = self.get_totp_offset()
        self.switch_id_offset = self.get_switch_id_offset()
        self.ingress_tstimestamp_offset = self.get_ingress_tstimestamp_offset()

    def get_ingress_tstimestamp_offset(self):
        eth_len = 14
        ip4_len = 20
        udp_len = 8
        total = eth_len + ip4_len + udp_len
        int_data_offset = 2 * total
        # print(int_data)
        # bit len
        # intl4_shim_t
        len_shim_int_type = 8
        len_shim_rsvd1 = 8
        len_shim_len = 8
        len_shim_dscp = 6
        len_rsvd3 = 2

        # int_header_t
        len_int_header_ver = 4
        len_int_header_rep = 2
        len_int_header_c = 1
        len_int_header_e = 1
        len_int_header_m = 1
        len_int_header_rsvd1 = 7
        len_int_header_rsvd2 = 3
        len_int_header_hop_metadata_len = 5
        len_int_header_remaining_hop_cnt = 8
        len_instruction_mk = 16
        len_int_header_seq = 16

        len_int_header = len_shim_int_type + len_shim_rsvd1 + len_shim_len + len_shim_dscp + len_rsvd3 \
            + len_int_header_ver + len_int_header_rep + len_int_header_c \
            + len_int_header_e + len_int_header_m + len_int_header_rsvd1 \
            + len_int_header_rsvd2 + len_int_header_hop_metadata_len + len_int_header_remaining_hop_cnt \
            + len_instruction_mk + len_int_header_seq
        
        telemetry_data_offset = int_data_offset + len_int_header // 4
        # print(telemetry_data)

        # int_q_occupancy_t
        len_q_id = 8
        len_q_occupancy = 24
        # int_hop_latency_t
        len_hop_latency = 32
        # int_port_ids_t
        len_ingress_port_id = 16
        len_egress_port_id = 16
        # int_switch_id_t
        len_switch_id = 32
        # int_egress_port_tx_util_t
        len_egress_port_tx_util = 32
        # int_level2_port_ids_t
        len_l2_ingress_port_id = 16
        len_l2_egress_port_id = 16
        # int_egress_tstamp_t
        len_egress_tstamp = 64
        # int_ingress_tstamp_t
        len_ingress_tstamp = 64

        len_telemetry_data = len_q_id + len_q_occupancy \
            + len_hop_latency + len_ingress_port_id + len_egress_port_id \
            + len_switch_id + len_egress_port_tx_util + len_l2_ingress_port_id + len_l2_egress_port_id \
            + len_egress_tstamp + len_ingress_tstamp
        # ingress_tstimestamp
        ingress_tstimestamp_offset = telemetry_data_offset + \
            + (len_switch_id + len_ingress_port_id + len_egress_port_id + len_hop_latency + len_q_id + len_q_occupancy) // 4 
        return ingress_tstimestamp_offset


    def get_totp_offset(self):
        eth_len = 14
        ip4_len = 20
        udp_len = 8
        total = eth_len + ip4_len + udp_len
        int_data_offset = 2 * total
        # print(int_data)
        # bit len
        # intl4_shim_t
        len_shim_int_type = 8
        len_shim_rsvd1 = 8
        len_shim_len = 8
        len_shim_dscp = 6
        len_rsvd3 = 2

        # int_header_t
        len_int_header_ver = 4
        len_int_header_rep = 2
        len_int_header_c = 1
        len_int_header_e = 1
        len_int_header_m = 1
        len_int_header_rsvd1 = 7
        len_int_header_rsvd2 = 3
        len_int_header_hop_metadata_len = 5
        len_int_header_remaining_hop_cnt = 8
        len_instruction_mk = 16
        len_int_header_seq = 16

        len_int_header = len_shim_int_type + len_shim_rsvd1 + len_shim_len + len_shim_dscp + len_rsvd3 \
            + len_int_header_ver + len_int_header_rep + len_int_header_c \
            + len_int_header_e + len_int_header_m + len_int_header_rsvd1 \
            + len_int_header_rsvd2 + len_int_header_hop_metadata_len + len_int_header_remaining_hop_cnt \
            + len_instruction_mk + len_int_header_seq
        
        telemetry_data_offset = int_data_offset + len_int_header // 4
        # print(telemetry_data)

        # int_q_occupancy_t
        len_q_id = 8
        len_q_occupancy = 24
        # int_hop_latency_t
        len_hop_latency = 32
        # int_port_ids_t
        len_ingress_port_id = 16
        len_egress_port_id = 16
        # int_switch_id_t
        len_switch_id = 32
        # int_egress_port_tx_util_t
        len_egress_port_tx_util = 32
        # int_level2_port_ids_t
        len_l2_ingress_port_id = 16
        len_l2_egress_port_id = 16
        # int_egress_tstamp_t
        len_egress_tstamp = 64
        # int_ingress_tstamp_t
        len_ingress_tstamp = 64

        len_telemetry_data = len_q_id + len_q_occupancy \
            + len_hop_latency + len_ingress_port_id + len_egress_port_id \
            + len_switch_id + len_egress_port_tx_util + len_l2_ingress_port_id + len_l2_egress_port_id \
            + len_egress_tstamp + len_ingress_tstamp
        # int_totp_code_t
        totp_code_offset = telemetry_data_offset + len_telemetry_data // 4 
        return totp_code_offset
    
    def get_switch_id_offset(self):
        eth_len = 14
        ip4_len = 20
        udp_len = 8
        total = eth_len + ip4_len + udp_len
        int_data_offset = 2 * total
        # print(int_data)
        # bit len
        # intl4_shim_t
        len_shim_int_type = 8
        len_shim_rsvd1 = 8
        len_shim_len = 8
        len_shim_dscp = 6
        len_rsvd3 = 2

        # int_header_t
        len_int_header_ver = 4
        len_int_header_rep = 2
        len_int_header_c = 1
        len_int_header_e = 1
        len_int_header_m = 1
        len_int_header_rsvd1 = 7
        len_int_header_rsvd2 = 3
        len_int_header_hop_metadata_len = 5
        len_int_header_remaining_hop_cnt = 8
        len_instruction_mk = 16
        len_int_header_seq = 16

        len_int_header = len_shim_int_type + len_shim_rsvd1 + len_shim_len + len_shim_dscp + len_rsvd3 \
            + len_int_header_ver + len_int_header_rep + len_int_header_c \
            + len_int_header_e + len_int_header_m + len_int_header_rsvd1 \
            + len_int_header_rsvd2 + len_int_header_hop_metadata_len + len_int_header_remaining_hop_cnt \
            + len_instruction_mk + len_int_header_seq
        
        telemetry_data_offset = int_data_offset + len_int_header // 4
        # print(telemetry_data)

        # int_q_occupancy_t
        len_q_id = 8
        len_q_occupancy = 24
        # int_hop_latency_t
        len_hop_latency = 32
        # int_port_ids_t
        len_ingress_port_id = 16
        len_egress_port_id = 16
        # int_switch_id_t
        len_switch_id = 32

        switch_id_offset = telemetry_data_offset 
        return switch_id_offset

    def udp_sniff(self):
        # filter = 'net fe80::dead:beef'
        filter = 'net 10.0.2.2'
        store = 1
        count = 0
        # packet = sniff(filter= filter, store = True, iface = self.interface,prn=lambda x:x.summary())
        def packet_sniff():
            packet = sniff(filter= filter, store = 1, iface = self.interface, prn = self.packet_process)
            print(packet)
        packet_sniff()
        # p = Process(target=packet_sniff)
        # print('--- udp sniff starting... ---')
        # p.start()
        # print('--- udp sniff started! ---')
        # p.join()

    def packet_process(self, packet):
        start_time = time.time()

        raw_packet = bytes_hex(packet)
        # print(raw_packet)
        totp_code = raw_packet[self.totp_offset : self.totp_offset + 8]
        print(totp_code)
        
        totp_code_ = int(str(totp_code)[2:-1], base = 16)
        print(totp_code_)

        switch_id = raw_packet[self.switch_id_offset : self.switch_id_offset + 8]
        print(switch_id)
        switch_id_ = int(str(switch_id)[2:-1], base = 16)
        print(switch_id_)

        end_time = time.time()
        fractional_seconds = time.perf_counter() % 1
        start_time_microseconds = int(start_time * 1e6) + int(fractional_seconds * 1e6)
        end_time_microseconds = int(end_time * 1e6) + int(fractional_seconds * 1e6)
        execution_time = end_time_microseconds - start_time_microseconds
        print(f"|||| execution time : {execution_time} us ||||")
        mq = self.message_queue.put({'switch_id': switch_id_, 'totp_code': totp_code_})

        ingress_timestamp = raw_packet[self.ingress_tstimestamp_offset: self.ingress_tstimestamp_offset + 16]
        egress_timestamp = raw_packet[self.ingress_tstimestamp_offset + 16 : self.ingress_tstimestamp_offset + 32]
        print(ingress_timestamp)
        ingress_timestamp_ = int(str(ingress_timestamp)[2:-1], base = 16)
        print(egress_timestamp)
        egress_timestamp_ = int(str(egress_timestamp)[2:-1], base = 16)
        packet_process_time = egress_timestamp_ - ingress_timestamp_
        print(f'@@ packet process time : {packet_process_time * 1e-6} ms @@' )


    def packet_show(self, packet):
        # layers = packet.layers()
        # self.print_layers(layers)

        print(packet)
        # print("--- parse ip ----")
        # self.parse_ip(packet)
        # print("--- parse ether ---")
        # self.parse_ether(packet)
        # print("--- parse ipv6 ---")
        # self.parse_ipv6(packet)

        # print("--- parse AH ---")
        # self.parse_AH(packet)
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
        # totp_code = bytes(seq).decode('utf8')
        # print(totp_code)
        print("--- icv ----")
        # icv --> Password entity identity，128bit
        icv = ah.icv
        print(icv)
        self.message_queue.put({'switch_id': spi, 'totp_code': seq})
        


    def print_layers(self, layers):
        for i in range(len(layers)):
            print("--- layer %s---", layers[i].__name__)
            print(layers[i])

    def start_udp_server(self, port):
        bufferSize  = 65565

        # Create a datagram socket
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port))
        print("UDP server up and listening at UDP port: %d" % port)

        # Listen for incoming datagrams
        while(True):
            message, address = sock.recvfrom(bufferSize)
            print("Received INT report (%d bytes) from: %s" % (len(message), str(address)))
            print(binascii.hexlify(message))
            # try:
            #     report = unpack_int_report(message)
            #     if report:
            #         collector.add_report(report)
            # except Exception as e:
            #     logger.exception("Exception during handling the INT report")


if __name__ == '__main__':
    print('--- packet_receiver starting... ---')
    udpReceiver = UdpReceiver(interface= 'veth22')
    # udpReceiver.udp_sniff()
  
  # 使用 time 函数获取秒级别的时间戳
    seconds = time.time()

    # 使用 perf_counter 函数获取相对高精度的时间戳
    fractional_seconds = time.perf_counter() % 1

    # 计算总的时间戳，精度在微秒级别
    current_time_microseconds = int(seconds * 1e6) + int(fractional_seconds * 1e6)

    # 打印当前时间的微秒级别表示
    print(f"Current time in microseconds: {current_time_microseconds}")

    # udpReceiver.start_udp_server(53)

    print('--- packet_receiver started!')
    # udpReceiver.udp_sniff()

    # totp_code = b'0000084b'
    # print(type(totp_code))
    # print(int(str(totp_code)[2:-1], base = 16))

