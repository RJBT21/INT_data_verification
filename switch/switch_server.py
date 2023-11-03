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
    initSyncController()
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
    data['switch_id'] = 's' + str(random.randint(1, 100))
    app.config['switch_id'] = data['switch_id']
    data['secret_key'] = TOTPUtil.generate_secret()
    data['echo_timestamp'] = cur_timestamp
    data['totp_code_length'] = random.randint(6,12)
    data['valid_interval'] = random.randint(15, 30)
    app.config['totp_tool'] = TOTPUtil(secret= data['secret_key'], 
                                       totp_code_length= data['totp_code_length'], 
                                       valid_interval= data['valid_interval'])

    HttpUtil.post(url=app.config['controller_switch_init_url'], data=data)

def check():
    for i in range(10):
        params = {}
        params['switch_id'] = app.config['switch_id']
        cur_timestamp = datetime.now().timestamp() - app.config['base_timestamp']
        params['totp_code'] = app.config['totp_tool'].generate_totp_code(cur_timestamp)
        HttpUtil.get(url=app.config['controller_switch_totp_code_verification_url'], params=params)
        time.sleep(5)

        
if __name__ == '__main__':
    print(os.path)
    app_init()
    app.run(debug = False, host = app.config['local_server_ip'], port = app.config['listen_port'])
    # check()