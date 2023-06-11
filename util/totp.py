import pyotp
import time
from datetime import datetime
from copy import deepcopy

class TOTP_util:
    def __init__(self, secret, totp_code_length, valid_interval) -> None:
        self.totp_code_length = totp_code_length
        self.valid_interval = valid_interval
        # self.secret = pyotp.random_base32
        self.secret = secret
        self.totp = pyotp.TOTP(s=self.secret, digits=self.totp_code_length, interval=self.valid_interval)

    def generate_totp_code(self, timestamp):
        pw = self.totp.at(for_time=timestamp)
        print('TOTP code : ', pw)
        return pw

    def verify(self, totp_code, timestamp):
        print('** now verify **')
        res = self.totp.verify(totp_code,for_time= timestamp, valid_window= 0)
        print('** verify result ** -> : ' + str(res))
        return res

    def get_remain_time(self):
        time_remaining = self.totp.interval - datetime.now().timestamp() % self.totp.interval
        print('** remain time ** -> ' + str(time_remaining))
        return time_remaining

    def get_local_time(self):
        now_time = datetime.now()
        print(now_time)
        return now_time

def totp_test():

    secret = pyotp.random_base32()
    print(secret)
    print('** generate totp pw **')
    print(datetime.now())
    totp = pyotp.TOTP(s=secret,interval=10,digits=8)
    pw = totp.now()
    print('TOTP code : ', pw)
    time_remaining = totp.interval - datetime.now().timestamp() % totp.interval
    print('** remain time ** -> ' + str(time_remaining))


    print('-------now verify---------')
    print(totp.verify(pw))
    print(datetime.now())
    time_remaining = totp.interval - datetime.now().timestamp() % totp.interval
    print('----remain time----' + str(time_remaining))
    for i in range(10):
        time.sleep(1)
        print('-------waited 1 secs---------' + 'order ' + str(i))
        print('TOTP code : ', totp.now())
        time_remaining = totp.interval - datetime.now().timestamp() % totp.interval
        print('----remain time----' + str(time_remaining))
        print(totp.verify(pw,valid_window=0,for_time=datetime.now()))
        print(datetime.now())

def totp_tool_test_2():
    totp_code_length = 10
    valid_interval = 10
    secret = pyotp.random_base32()
    print(secret)
    # print(datetime.now().timestamp())
    # time.sleep(1)
    # print(datetime.now().timestamp())

    timestamp_str = str(datetime.now().timestamp())
    print(timestamp_str)
    timestamp_float = float(timestamp_str)
    print(timestamp_float)

    totp_tool1 = TOTP_util(secret=secret, totp_code_length=totp_code_length, valid_interval=valid_interval)
    totp_tool2 = TOTP_util(secret=secret, totp_code_length=totp_code_length, valid_interval=valid_interval)
    
    pw1 = totp_tool1.generate_totp_code()
    pw2 = totp_tool2.generate_totp_code()
    totp_tool1.get_remain_time()
    totp_tool2.get_remain_time()

    totp_tool1.verify(pw1)
    totp_tool2.verify(pw1)

    totp_tool1.verify(pw2)
    totp_tool2.verify(pw2)

def totp_tool_test():
    totp_code_length = 10
    valid_interval = 10
    totp_tool = TOTP_util(totp_code_length=totp_code_length, valid_interval=valid_interval)

    pw = totp_tool.generate_totp_code()
    totp_tool.get_local_time()
    totp_tool.get_remain_time()

    totp_tool.verify(pw)
    totp_tool.get_local_time()
    totp_tool.get_remain_time()

    for i in range(10):
        time.sleep(1)
        print('-------waited 1 secs---------' + 'order ' + str(i))
        totp_tool.generate_totp_code()
        totp_tool.get_remain_time()
        totp_tool.verify(pw)
        totp_tool.get_local_time()
    
def totp_tool_test_3():
    secret = pyotp.random_base32()
    totp_code_length = 10
    valid_interval = 30

    base_timestamp = datetime.now().timestamp() - 60 * 60 * 2
    cur_timestamp = datetime.now().timestamp()
    running_timestamp = cur_timestamp - base_timestamp
    print(running_timestamp)

    totp_tool = TOTP_util(secret= secret, totp_code_length= totp_code_length, valid_interval= valid_interval)
    pw = totp_tool.generate_totp_code(running_timestamp)

    totp_tool.get_remain_time()
    
    verification_timestamp = datetime.now().timestamp() - base_timestamp
    totp_tool.verify(pw, verification_timestamp)

if __name__ == '__main__':
    # totp_test()
    # totp_tool_test()
    # totp_tool_test_2()
    totp_tool_test_3()