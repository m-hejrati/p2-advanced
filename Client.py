
import requests


url = 'http://localhost:8765'

response = requests.get(url)
print(response.status_code)
print(response.text)

print()

myPostData = {'myPostKey': 'myPostValue'}
response = requests.post(url, data = myPostData)
print(response.status_code)
print(response.text)

print()

myPutData = {'myPutKey': 'myPutValue'}
response = requests.put(url, data = myPutData)
print(response.status_code)
print(response.text)
