import sys
sys.path.append('..')
from util.totp import TOTPUtil
from datetime import datetime


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