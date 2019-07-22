from urllib import request, parse
import json

data = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "user.login",
            "params": {
                "user": "Admin",
                "password": "zabbix"
            },
            "id": 0
        }
).encode('utf-8')
header = {
        "Content-Type": "application/json"
}
url = "http://172.20.6.112/api_jsonrpc.php"
r = request.Request(url, data=data, headers=header)
response = request.urlopen(r)
print(response.read())
