
import requests


url = 'http://localhost:8765'


mydata = {'mykey': 'myvalue'}
response = requests.post(url, data = mydata)
print(response.status_code)
print(response.text)

print()

response = requests.put(url, data = mydata)
print(response.status_code)
print(response.text)

print()

response = requests.get(url)
print(response.status_code)
print(response.text)
