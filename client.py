import socket

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 7777

if __name__ == '__main__':
    print('CONNECTING TO {}:{}'.format(SERVER_HOST, SERVER_PORT))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print('CONNECTED')

        while True:
            data = sock.recv(2048)
            if len(data) == 0: # how the python library signifies the peer closing the connection
                break
            print('GOT: {}'.format(data.decode('utf-8')))
        print('DISCONNECTED')
