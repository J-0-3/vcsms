import socket
import random
from queue import Queue
import json 
import threading
import keys
import signing
from cryptographylib import dhke, sha256, aes256, utils
port = 6000
interface = "0.0.0.0"

class Server:
    def __init__(self, addr: str, port: int, keypair: tuple):
        self.addr = addr
        self.port = port
        self.pub = keypair[0]
        self.priv = keypair[1]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.encryption_keys = {}
        self.dhke_group = dhke.group16_4096
        self.in_queue = Queue()
        self.out_queue = Queue()
        self.client_in_queues = {}
        
        
    def handshake(self, client: socket.socket):
        pub_exp = hex(self.pub[0])[2:].encode()
        pub_mod = hex(self.pub[1])[2:].encode()
        client.send(pub_exp+b':'+pub_mod)
        auth_packet = client.recv(2048)
        c_id, c_exp, c_mod = auth_packet.split(b':')
        client_pubkey = (int(c_exp, 16), int(c_mod, 16))
        if keys.fingerprint(client_pubkey) != int(c_id, 16):
            client.send(b"PUBLIC KEY VALIDATION FAILED")
            client.close()
            return 

        dhke_priv = random.randrange(1, self.dhke_group[1])
        dhke_pub = hex(dhke.generate_public_key(dhke_priv, self.dhke_group))[2:].encode()
        dhke_pub_sig = signing.sign(dhke_pub, self.priv)
        client.send(dhke_pub+b":"+dhke_pub_sig)

        c_dhke_pub, c_dhke_pub_sig = client.recv(2048).split(b':')

        if not signing.verify(c_dhke_pub, c_dhke_pub_sig, client_pubkey):
            client.send(b"SIGNATURE VERIFICATION FAILED")
            client.close()
            return

        shared_key = dhke.calculate_shared_key(dhke_priv, int(c_dhke_pub, 16), self.dhke_group)
    
        self.encryption_keys[client] = sha256.hash(utils.i_to_b(shared_key))
        self.client_in_queues[client] = Queue()
        
        gateway_thread = threading.Thread(target=self.in_thread, args=(client, ), daemon=True)
        gateway_thread.start()

    def in_thread(self, client: socket.socket):
        while True:
            dat = client.recv(2048)
            if dat == b'':
                continue
                
            iv, data = dat.split(b':')
            iv = int(iv, 16)
            data = aes256.decrypt_cbc(utils.i_to_b(int(data, 16)), self.encryption_keys[client], iv)
            self.in_queue.put({"from": client, "data": data})
    
    def out_thread(self):
        while True:
            message = self.out_queue.get()
            client = message["to"]
            data = message["data"]
            key = self.encryption_keys[client]
            iv = random.randrange(1, 2**128)
            encrypted = hex(int.from_bytes(aes256.encrypt_cbc(data, key, iv)))[2:].encode()
            client.send(hex(iv)[2:].encode()+ b':' + encrypted)
    
    def sort_incoming(self):
        while True:
            message = self.in_queue.get()
            client = message["from"]
            data = message["data"]
            self.client_in_queues[client].put(data)
            print(f"MESSAGE: {data.decode()}")      
                
    def connect(self, client: socket.socket):
        self.handshake(client)
        self.send(client, b'Hello client!')
        
    def send(self, client: socket.socket, message: bytes):
        self.out_queue.put({"to":client, "data":message})
    
    def accept_thread(self):
        while True:
            conn, addr = self.sock.accept()
            t_connect = threading.Thread(target=self.connect, args=(conn, ))
            t_connect.start()
            
    def run(self):
        self.sock.bind((self.addr, self.port))
        self.sock.listen(30)
        
        t_sort = threading.Thread(target=self.sort_incoming, args=())
        t_sort.start()
        t_out = threading.Thread(target=self.out_thread, args=())
        t_out.start()
        t_accept = threading.Thread(target=self.accept_thread, args=())
        t_accept.start()
        
            
if __name__ == "__main__":
    keypair = keys.load_keys("server.pub", "server.priv")
    with open("server.conf", 'w') as f:
        f.write(json.dumps({
            "ip": "0.0.0.0",
            "port": 6000,
            "fingerprint": hex(keys.fingerprint(keypair[0]))[2:]
        }))
    server = Server("0.0.0.0", 6000, keypair)
    server.run() 