import requests

class HttpUtil:
	def __init__(self) -> None:
		pass

	def get(url, params):
		res = requests.get(url=url, params=params)
		print(res.text)
		return res.text

	def post(url, data):
		print('url = ' + url)
		print('data = ')
		print(data)
		res = requests.post(url=url, json=data)
		return res.text
		
