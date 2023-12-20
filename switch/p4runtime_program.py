import sys
sys.path.append('..')
from util.totp import TOTPUtil
from datetime import datetime
from table_grpc import TableGrpcConnector
from ipaddress import IPv6Address as ipv6

class TOTPHandler(object):
    def __init__(self, secret, valid_interval, totp_code_length) -> None:
        self.secert = secret
        self.valid_interval = valid_interval
        self.totp_code_length = totp_code_length
        self.totp_tool = TOTPUtil(self.secert, self.totp_code_length, self.valid_interval)

    def password_generate(self):
        timestamp = datetime.now().timestamp()
        totp_code = self.totp_tool.generate_totp_code(timestamp)
        return totp_code


if __name__ == '__main__':
    secret = '3RJRTNTESDZ57ZLYJ7CBXWHDUPDY44NO'
    valid_interval = 30
    totp_code_length = 10
    totp_handler = TOTPHandler(secret, valid_interval, totp_code_length)
    totp_code = totp_handler.password_generate()
    print(totp_code)
    grpc_addr = '127.0.0.1:50052'
    table_operator = TableGrpcConnector(grpc_addr=grpc_addr)
    # table_name = 'totp'
    # action_name = 'totp_implement'
    # data_str_totp = 'name=totp_code,val=' + str(totp_code)
    # data_tuple_totp_code = table_operator.get_data_tuple_from_input(data_str_totp)
    # print(data_tuple_totp_code)

    # port = 2
    # data_str_port = 'name=port,val=' + str(port)
    # data_tuple_port = table_operator.get_data_tuple_from_input(data_str_port)
    # print(data_tuple_port)

    # ip_value = int(ipv6('fe80::1234'))
    # key_str = "name=hdr.ipv6.dstAddr,value=" + str(ip_value)
    # key_tuple = table_operator.get_key_tuple_from_input(key_str)
    # print(key_tuple)
    # table_operator.add_entry(table_name=table_name, key_tuples=[key_tuple], data_tuples=[data_tuple_totp_code, data_tuple_port], action_name=action_name)
    
    # table_name = 'send'
    # action_name = 'send_ipv6'

    # port = 2
    # data_str_port = 'name=port,val=' + str(port)
    # data_tuple_port = table_operator.get_data_tuple_from_input(data_str_port)
    # print(data_tuple_port)

    # ip_value = int(ipv6('fe80::2345'))
    # key_str = "name=hdr.ipv6.dstAddr,value=" + str(ip_value)
    # key_tuple = table_operator.get_key_tuple_from_input(key_str)
    # print(key_tuple)
    # table_operator.add_entry(table_name=table_name, key_tuples=[key_tuple], data_tuples=[data_tuple_port], action_name=action_name)

    table_name = 'Int_transit.tb_totp_code'
    action_name = 'int_totp_header_set'

    key_str = 'name=hdr.int_header.instruction_mk,value=' + str(int(0xFF00))
    key_tuple = table_operator.get_key_tuple_from_input(key_str)

    data_str = 'name=totp_code,val=4294967295'
    data_tuple = table_operator.get_data_tuple_from_input(data_str)

    table_operator.mod_entry(table_name=table_name, key_tuples=[key_tuple], data_tuples=[data_tuple], action_name=action_name)
