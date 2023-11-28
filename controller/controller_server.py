from flask import Flask, request, make_response
import yaml
import os
import sys
sys.path.append('..')
from util.totp import TOTPUtil
from util.mysql_util import MysqlDB
from datetime import datetime
from util.packet_receiver import UdpReceiver
import threading

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
    app.config['totp_tool_dict'] = {}

    app.config['mysql_host'] = conf['MYSQL']['HOST']
    app.config['mysql_user_name'] = conf['MYSQL']['USER']
    app.config['mysql_port'] = conf['MYSQL']['PORT']
    app.config['mysql_password'] = conf['MYSQL']['PASSWORD']
    app.config['mysql_database_name'] = conf['MYSQL']['DATABASE_NAME']

    app.config['mysql_tool'] = MysqlDB(
        host= app.config['mysql_host'], 
        port= app.config['mysql_port'], 
        user= app.config['mysql_user_name'], 
        password= app.config['mysql_password'],
        db= app.config['mysql_database_name'])

    app.config['udp_receiver'] = UdpReceiver(interface= 'ens33')

    # sniff_int_packets()

def add_switch_info(data):
    sql_dict = {}
    # sql_dict['id'] = 'null'
    sql_dict['switch_id'] = data['switch_id']
    sql_dict['secret_key'] = data['secret_key']
    sql_dict['echo_timestamp'] = data['echo_timestamp']
    sql_dict['totp_code_length'] = data['totp_code_length']
    sql_dict['valid_interval'] = data['valid_interval']
    table = 'switch_info'

    SQL = 'insert into ' + '`' + table + '`('
    key_list = sql_dict.keys()
    for key in key_list:
        SQL = SQL + '`' + key + '`' + ','
    SQL = SQL.strip(',') + ')'
    SQL = SQL + ' values ('
    for key in key_list:
        if isinstance(sql_dict[key], int) or isinstance(sql_dict[key], float):
            SQL = SQL + str(sql_dict[key]) + ','
        elif isinstance(sql_dict[key], str):
            SQL = SQL + '\"' + sql_dict[key] + '\"' + ','
    SQL = SQL.strip(',') + ')'
    try:
        print(SQL)
        app.config['mysql_tool'].exec_db(SQL)
        return True
    except:
        return False
    
def delete_switch_info(data):
    key = 'switch_id'
    value = data['switch_id']
    
    table = 'switch_info' 
    
    SQL = 'delete from ' + '`' + table + '` where '
    SQL = SQL + '`' + key + '` = \"' + value + '\"'
    try:
        app.config['mysql_tool'].exec_db(SQL)
        return True
    except:
        return False

def query_switch_info(data):
    key = 'switch_id'
    value = data['switch_id']

    table = 'switch_info'

    SQL = 'select * from ' + '`' + table + '`'
    SQL = SQL + ' where`' + key + '` = \"' + value + '\"'
    try:
        result = app.config['mysql_tool'].select_db(SQL)
        return result
    except:
        return False

@app.route('/password_config', methods = ['POST'])
def totp_code_config():
    data = request.get_json()
    totp_code_length = data['totp_code_length']
    valid_interval = data['valid_interval']
    secret = data['secret']
    app.config['totp_tool'] = TOTPUtil(secret= secret, totp_code_length= totp_code_length, valid_interval= valid_interval)
    return make_response('succeed', 200)

@app.route('/password_verification', methods = ['POST'])
def totp_code_verification():
    data = request.get_json()
    totp_code = data['totp_code']
    totp_tool = app.config['totp_tool']
    if not totp_tool:
        response = make_response('totp has not inited','500')
        return response
    is_passed = totp_tool.verify(totp_code)
    if is_passed:
        res = 'accessed'
    else:
        res = 'not accessed'
    return make_response(res, 200)

@app.route('/switch_info',methods = ['POST'])
def switch_info_add():
    data = request.get_json()
    print(data)
    result = add_switch_info(data)
    if result:
        
        response = make_response('succeed',200)
    else:
        response = make_response('failed',400)
    return response

@app.route('/switch_info',methods = ['DELETE'])
def switch_info_delete():
    data = request.get_json()
    result = delete_switch_info(data)
    if result:
        response = make_response('succeed',200)
    else:
        response = make_response('failed',400)
    return response

@app.route('/totp_code_verification',methods = ['GET'])
def verification_totp_with_switch_id():
    switch_id = request.args.get('switch_id')
    totp_code = request.args.get('totp_code')
    result = verification_totp_at_switch(switch_id, totp_code)
    if not result:
        response_content = 'related switch info not found'
        return make_response(response_content, 400)
    is_accessed = result[0]
    if is_accessed:
        response_content = result[1]
    else:
        response_content = result[1]
    # response_content = 'verification is todo.'
    return make_response(response_content, 200)

def verification_totp_at_switch(switch_id,totp_code):
    data = {'switch_id':switch_id}
    result = query_switch_info(data)
    print("---- switch_info query result ----")
    print(result)
    if not result:
        return False
    switch_info = result[0]
    switch_id = switch_info['switch_id']
    secret_key = switch_info['secret_key']
    echo_timestamp = switch_info['echo_timestamp']
    totp_code_length = switch_info['totp_code_length']
    valid_interval = switch_info['valid_interval']
    
    verification_result = " "
    # if switch_id not in app.config['totp_tool_dict'].keys():
    #     verification_result = "totp on this switch is not configured!"
    #     return verification_result

    base_timestamp = float(echo_timestamp)
    print("---- base timestamp ----")
    print(base_timestamp)
    totp_tool = TOTPUtil(secret= secret_key, totp_code_length= totp_code_length, valid_interval= valid_interval)
    verification_timestamp = datetime.now().timestamp() - base_timestamp
    print("---- verfication timestamp ----")
    print(verification_timestamp)
    print("---- totp_code valid remain time ----")
    totp_tool.get_remain_time_at(verification_timestamp)

    # add '0' to totp_code's head to up totp_code_length
    if totp_code_length != len(totp_code):
        totp_code = '0' * (totp_code_length - len(totp_code))  + totp_code

    totp_verification_result = totp_tool.verify(totp_code= totp_code, timestamp= verification_timestamp)
    if totp_verification_result:
        verification_result = [True, 'totp verification succeed.']
    else:
        verification_result = [False, 'totp verification failed.']
    return verification_result

def sniff_int_packets():
    print('--- sniff int process initing... ---')
    udp_receiver = app.config['udp_receiver']
    def run_job_udp_sniff():
        udp_receiver.udp_sniff()
        
    
    def run_job_mq_get():
        mq = udp_receiver.message_queue
        while True:
            while mq.empty() is not True:
                print('** queue size: {} **'.format(mq.qsize()))
                print("--- message geted ---")
                message = mq.get()
                # print(message)
                switch_id = 's' + str(message['switch_id'])
                totp_code = str(message['totp_code'])
                print('--- totp verifying switch_id:{} , totp_code:{} ---'.format(switch_id, totp_code))
                result = verification_totp_at_switch(switch_id, totp_code)
                print("--- packet verification result: {}".format(result))
                # print(threading.enumerate())
    
    thread_sniff = threading.Thread(target=run_job_udp_sniff)
    thread_sniff.start()
    thread_mq_get = threading.Thread(target=run_job_mq_get)
    thread_mq_get.start()


if __name__ == '__main__':
    print(os.path)
    app_init()
    app.run(debug = True, host = app.config['local_server_ip'], port = app.config['listen_port'])
