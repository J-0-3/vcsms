import socket
import random
from cryptographylib import rsa, sha256, dhke, utils, aes256
import signing
server = ("127.0.0.1", 4000)
dhke_group = dhke.group16_4096

def handshake(server: socket.socket, pub_key: tuple, priv_key: tuple):
    pub_exp = hex(pub_key[0])[2:].encode()
    pub_mod = hex(pub_key[1])[2:].encode()
    
    server_exp, server_mod = server.recv(2048).split(b':')
    server_pub = (int(server_exp, 16), int(server_mod, 16))
    
    pub_key_hash = hex(sha256.hash(pub_exp + pub_mod))[2:].encode()
    server.send(pub_key_hash+b":"+pub_exp+b":"+pub_mod)
    print("exchanged public keys...")
    dhke_priv = random.randrange(1, dhke_group[1])
    dhke_pub = hex(dhke.generate_public_key(dhke_priv, dhke_group))[2:].encode()
    dhke_pub_sig = signing.sign(dhke_pub, priv_key)

    s_dhke_pub, s_dhke_pub_sig = server.recv(2048).split(b':')

    if not signing.verify(s_dhke_pub, s_dhke_pub_sig, server_pub):
        server.send("SIGNATURE VERIFICATION FAILED")
        server.close()
        return
    
    server.send(dhke_pub+b":"+dhke_pub_sig)

    shared_key = dhke.calculate_shared_key(dhke_priv, int(s_dhke_pub, 16), dhke_group)
    # print(f"ESTABLISHED KEY: {hex(shared_key)}")
    print("established encryption key...")
    derived_aes_key = sha256.hash(utils.i_to_b(shared_key))
    print("connected.")
    message = input("enter message for server: ").encode()
    encrypted_message = aes256.encrypt_cbc(message, derived_aes_key, 203740925691429429542835616606368968923)
    server.send(encrypted_message)
    
if __name__ == "__main__":
    print("generating rsa key...")
    pub, priv = rsa.gen_keypair(2048)
    print("done. connecting to server...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(server)
    handshake(s, pub, priv)