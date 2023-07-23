from flask import Flask, request, make_response
import yaml
import os
import sys
from datetime import datetime
sys.path.append('..')
from util.totp import TOTPUtil

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
    app.config['base_timestamp'] = 1686040972.55786

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


if __name__ == '__main__':
    print(os.path)
    app_init()
    app.run(debug = False, host = app.config['local_server_ip'], port = app.config['listen_port'])