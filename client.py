import json
import threading
from server_connection import serverConnection
import keys



def listen_thread(server: serverConnection):
    while True:
        message = server.read().decode()
        print(f"New message from server: {message}")

def send_thread(server: serverConnection):
    while True:
        message = input("enter message: ")
        server.send(message.encode())
    
if __name__ == "__main__":
    with open("server.conf", 'r') as conf:
        server = json.loads(conf.read())    
    try:
        pub, priv = keys.load_keys("client.pub", "client.priv")
    except FileNotFoundError:
        pub, priv = keys.generate_keys("client.pub", "client.priv")
    s = serverConnection(server["ip"], server["port"], server["fingerprint"])
    s.connect(pub, priv)
    
    t_listen = threading.Thread(target=listen_thread, args=(s, ))
    t_send = threading.Thread(target=send_thread, args=(s, ))
    t_listen.start()
    t_send.start()
    