import requests
import json

ip = "127.0.0.1"

"""
abuseipdb_api_key = '4984730b825fcf3c930a3e40401b941ace59314d965be55525721a59702f68a8b43514d41f7625fa'  #change your abuseipdb_api_key
days = 90
request = "https://www.abuseipdb.com/check/" + ip + "/json?"
params = {'key': abuseipdb_api_key, 'days': days}
r = requests.get(request, params = params)

print(r.url)
print(r.status_code)
print(r.text)
"""



import requests

auth0_api_key = "834d4a7b-5d91-4ba4-9e54-1702f8e9da7e"
def check_ip_malicious_auth0(ip):
	
	url = "https://signals.api.auth0.com/v2.0/ip/" + ip

	headers = {
		'accept': "application/json",
		'x-auth-token': auth0_api_key
		}

	response = requests.request("GET", url, headers=headers)
	y = json.loads(response.text)
	malicious_score = y["fullip"]
	print(malicious_score)
	
check_ip_malicious_auth0("117.18.232.200")
