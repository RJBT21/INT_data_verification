import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

class EncryptUtil():
	def __init__(self) -> None:
		self.key = None
		self.iv = None
		pass

	def encrypt(self, data):
		# 参数key: 秘钥，要求是bytes类型，并且长度必须是16、24或32 bytes，因为秘钥的长度可以为：128位、192位、256位
		# 参数mode: 加密的模式，有ECB、CBC等等，最常用的是CBC
		# 参数iv: 初始向量，是CBC加密模式需要的初始向量，类似于加密算法中的盐
		# 创建用于加密的AES对象
		key = b"1234123412ABCDEF"
		iv = b"ABCDEF1234123412"
		cipher1 = AES.new(key, AES.MODE_CBC, iv)
		# 使用对象进行加密，加密的时候，需要使用pad对数据进行填充，因为加密的数据要求必须是能被128整除
		# pad参数内容，第一个是待填充的数据，第二个是填充成多大的数据，需要填充成128位即16bytes
		ct = cipher1.encrypt(pad(data, 16))
		# 将加密后的结果（二进制）转换成十六进制的或者其它形式
		ct_hex = binascii.b2a_hex(ct)
		return ct_hex


	def decrypt(self, ct_hex):
		key = b"1234123412ABCDEF"
		iv = b"ABCDEF1234123412"
		# 创建用于解密的AES对象
		cipher2 = AES.new(key, AES.MODE_CBC, iv)
		# 将十六进制的数据转换成二进制
		hex_data = binascii.a2b_hex(ct_hex)
		# 解密完成后，需要对数据进行取消填充，获取原来的数据
		pt = unpad(cipher2.decrypt(hex_data), 16)
		return pt
