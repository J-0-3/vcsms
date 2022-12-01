import socket
import threading
import random
import json
from cryptographylib import sha256, dhke, utils, aes256
import signing
import keys
import sys
import http.server

dhke_group = dhke.group16_4096
address = ("0.0.0.0", 6000)

def accept_client(client: socket.socket, pub_key: tuple, priv_key: tuple):
    pub_exp = hex(pub_key[0])[2:].encode()
    pub_mod = hex(pub_key[1])[2:].encode()
    client.send(pub_exp+b':'+pub_mod)
    auth_packet = client.recv(2048)
    c_id, c_exp, c_mod = auth_packet.split(b':')
    if sha256.hash(c_exp+c_mod) != int(c_id, 16):
        client.send(b"PUBLIC KEY VALIDATION FAILED")
        client.close()
        return 
    client_pubkey = (int(c_exp, 16), int(c_mod, 16))
    
    dhke_priv = random.randrange(1, dhke_group[1])
    dhke_pub = hex(dhke.generate_public_key(dhke_priv, dhke_group))[2:].encode()
    dhke_pub_sig = signing.sign(dhke_pub, priv_key)
    client.send(dhke_pub+b":"+dhke_pub_sig)

    c_dhke_pub, c_dhke_pub_sig = client.recv(2048).split(b':')

    if not signing.verify(c_dhke_pub, c_dhke_pub_sig, client_pubkey):
        client.send(b"SIGNATURE VERIFICATION FAILED")
        client.close()
        return

    shared_key = dhke.calculate_shared_key(dhke_priv, int(c_dhke_pub, 16), dhke_group)
    # print(f"ESTABLISHED KEY: {hex(shared_key)}")
    
    derived_aes_key = sha256.hash(utils.i_to_b(shared_key))
    recieved_message = client.recv(2048)
    message = aes256.decrypt_cbc(recieved_message, derived_aes_key, 203740925691429429542835616606368968923)
    print(f"RECEIVED: {message}")
    
if __name__ == "__main__":
    if len(sys.argv) > 3 and sys.argv[3] == '-g':
        print("generating keypair")
        keys.generate_keys("server.pub", "server.priv")
    
    pub, priv = keys.load_keys("server.pub", "server.priv")
               
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if len(sys.argv) > 1:
        address = (address[0], int(sys.argv[1]))
    if len(sys.argv) > 2:
        address = (sys.argv[2], address[1]) 
        
    with open("server.conf", 'w') as f:
        f.write(json.dumps({
            "ip": address[0],
            "port": address[1],
            "fingerprint": keys.fingerprint(pub)
        })) 
    s.bind(address)
    s.listen()
    print("LISTENING")
    
    while True:
        conn, addr = s.accept()
        t_accept = threading.Thread(target=accept_client, 
                                    args=(conn, pub, priv))
        t_accept.start()