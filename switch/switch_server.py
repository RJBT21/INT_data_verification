from flask import Flask, request, make_response
import yaml
import os
import sys
import time
from datetime import datetime
from numpy import random
sys.path.append('..')
from util.totp import TOTPUtil
from util.httpClient import HttpUtil 
from table_grpc import TableGrpcConnector
from ipaddress import IPv6Address as ipv6

app = Flask(__name__)

def read_yaml(path):
    with open(path, 'rb') as f:
        cf = f.read()
    cf = yaml.full_load(cf)
    return cf

def app_init():
    root = os.getcwd()
    config_file = os.path.join(root, 'config.yaml')
    conf = read_yaml(config_file)
    app.config['local_server_ip'] = conf['LOCAL_SERVER_IP']
    app.config['listen_port'] = int(conf['LISTEN_PORT'])
    app.config['totp_tool'] = None
    app.config['controller_switch_init_url'] = conf['CONTROLLER_SWITCH_INIT_URL']
    app.config['controller_switch_totp_code_verification_url'] = conf['CONTROLLER_SWITCH_TOTP_CODE_VERIFICATION_URL']
    app.config['switch_grpc_address'] = conf['SWITCH_GRPC_ADDRESS']
    app.config['grpc_connector'] = TableGrpcConnector(app.config['switch_grpc_address'])

    initSyncController()
    passwordAutoUpdate()
    check()

@app.route('/password_config', methods = ['POST'])
def totp_code_config():
    data = request.get_json()
    totp_code_length = data['totp_code_length']
    valid_interval = data['valid_interval']
    secret = data['secret']
    app.config['totp_tool'] = TOTPUtil(secret= secret, totp_code_length= totp_code_length, valid_interval= valid_interval)
    return make_response('succeed', 200)

@app.route('/get_password', methods = ['GET'])
def get_totp_code():
    totp_tool = app.config['totp_tool']
    print(totp_tool)
    cur_timestamp = datetime.now().timestamp() - app.config['base_timestamp']
    password = totp_tool.generate_totp_code(cur_timestamp)
    generate_time = totp_tool.get_local_time()
    remain_time = totp_tool.get_remain_time_at(cur_timestamp)
    response_content = {"password": password, "generate_time": generate_time, "remain_time": str(remain_time)}
    return make_response(response_content, 200)

def initSyncController():
    cur_timestamp = datetime.now().timestamp()
    app.config['base_timestamp'] = cur_timestamp
    data = {}
    switch_id = random.randint(1, 100)
    data['switch_id'] = 's' + str(switch_id)
    app.config['switch_id'] = data['switch_id']
    data['secret_key'] = TOTPUtil.generate_secret()
    data['echo_timestamp'] = cur_timestamp
    data['totp_code_length'] = random.randint(6,9)
    data['valid_interval'] = random.randint(10, 15)
    app.config['totp_tool'] = TOTPUtil(secret= data['secret_key'], 
                                       totp_code_length= data['totp_code_length'], 
                                       valid_interval= data['valid_interval'])
    setSwitchIdToTable(switch_id)
    HttpUtil.post(url=app.config['controller_switch_init_url'], data=data)

def passwordAutoUpdate():
    totp_tool = app.config['totp_tool']
    cur_timestamp = datetime.now().timestamp() - app.config['base_timestamp']
    remain_time = totp_tool.get_remain_time_at(cur_timestamp)
    while(True):
        remain_time = totp_tool.get_remain_time_at(cur_timestamp)
        time.sleep(remain_time)
        cur_timestamp = datetime.now().timestamp() - app.config['base_timestamp']
        # 更新密码到P4交换机中
        totp_code = totp_tool.generate_totp_code(cur_timestamp)
        setPasswordToTable(totp_code)

def setPasswordToTable(totp_code):
    table_operator = app.config['grpc_connector']
    table_name = 'Int_transit.tb_totp_code'
    action_name = 'int_totp_header_set'

    data_str_totp = 'name=totp_code,val=' + str(totp_code)
    data_tuple_totp_code = table_operator.get_data_tuple_from_input(data_str_totp)

    intstruction_mk = 0xFF00
    key_str = 'name=hdr.int_header.instruction_mk,value=' + str(int(intstruction_mk))
    key_tuple = table_operator.get_key_tuple_from_input(key_str)

    table_operator.mod_entry(table_name=table_name, key_tuples=[key_tuple], data_tuples=[data_tuple_totp_code], action_name=action_name)

    # print(data_tuple_totp_code)

def setSwitchIdToTable(switch_id):
    table_operator = app.config['grpc_connector']
    table_name = 'Int_transit.tb_int_transit'
    action_name = 'configure_transit'

    data_str_switch_id = 'name=switch_id,val=' + str(switch_id)
    data_tuple_switch_id = table_operator.get_data_tuple_from_input(data_str_switch_id)

    data_str_l3_mtu = 'name=l3_mtu,val=' + str(1500)
    data_tuple_l3_mtu = table_operator.get_data_tuple_from_input(data_str_l3_mtu)

    table_operator.set_default_entry(table_name=table_name, data_tuples=[data_tuple_switch_id, data_tuple_l3_mtu], action_name=action_name)

def check():
    print('starting checking....')
    for i in range(10):
        params = {}
        params['switch_id'] = app.config['switch_id']
        cur_timestamp = datetime.now().timestamp() - app.config['base_timestamp']
        params['totp_code'] = app.config['totp_tool'].generate_totp_code(cur_timestamp)
        response = HttpUtil.get(url=app.config['controller_switch_totp_code_verification_url'], params=params)
        print(response)
        time.sleep(5)

        
if __name__ == '__main__':
    print(os.path)
    app_init()
    app.run(debug = False, host = app.config['local_server_ip'], port = app.config['listen_port'])
    check()